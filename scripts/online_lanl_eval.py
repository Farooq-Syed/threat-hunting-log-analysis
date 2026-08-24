"""Online stateful Threat Hunting evaluation over the LANL eval frame.

Implements the full locked protocol's detector set as an *online stateful* evaluator. For each
(src_user, src_computer) key we keep only the state each detector needs:

  * brute-force:      running failure count, first time it reached the threshold.
  * burst:            a bounded deque of recent failure timestamps (trailing window) and the
                      first time >= min_failures fell within a window.
  * success-after-failure: running failure count reset on success; the first success that
                      arrives with a run >= threshold (alert at that success time).
  * lateral-change:   recent-success (time, src) trail per user; the first success from a new
                      source inside the window.

Events are processed in **chronological order** (the frame is time-sorted via SQLite). An
alert is emitted the first time a detector's threshold is crossed, and the crossing timestamp
is the alert time — so time-to-detection is the delay from the red-team event to that first
crossing, never the last failure. Matching is a-priori: an alert matches the next red-team
event for the same key within the delay window (no look-ahead).

Memory-safe: per-key state is bounded (counts + a small deque + a recent-success trail); the
full event sequence is never held in RAM. The SQLite per-key-counts pass used during
development is a performance diagnostic only; this is the publication pipeline.

Usage:
  python scripts/online_lanl_eval.py --input data/lanl_eval_frame.parquet \
      --redteam <redteam>.gz --split-day 15 --delay-minutes 30 \
      --failed-threshold 5 --window-minutes 5 --lateral-hours 24 \
      --output results/lanl_online.json
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sqlite3
import time
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

DAY_SECONDS = 86400


def _redteam(path: Path) -> pd.DataFrame:
    rows = []
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) != 4:
                continue
            try:
                rows.append({"time": int(row[0]), "user": row[1].strip(),
                             "src": row[2].strip(), "dst": row[3].strip()})
            except ValueError:
                continue
    return pd.DataFrame(rows)


def _build_sorted_sqlite(frame_path: Path, db_path: Path) -> None:
    """Stream the frame into a SQLite table with a time-first index (chronological order)."""
    import sqlite3 as sq

    conn = sq.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS ev")
    conn.execute("CREATE TABLE ev (time INT, src_user TEXT, src_computer TEXT, "
                 "dst_computer TEXT, status TEXT, day INT)")
    pf = pq.ParquetFile(frame_path)
    total = 0
    buf = []
    for batch in pf.iter_batches(batch_size=1_000_000, columns=[
            "time", "src_user", "src_computer", "dst_computer", "status"]):
        t = batch.to_pandas()
        t["status"] = t["status"].str.strip().str.lower().map(
            lambda s: "failed" if s in ("fail", "failed", "failure") else "success")
        t["day"] = (t["time"] // DAY_SECONDS).astype(int)
        buf.extend(t[["time", "src_user", "src_computer", "dst_computer", "status", "day"]]
                   .itertuples(index=False, name=None))
        if len(buf) >= 2_000_000:
            conn.executemany("INSERT INTO ev VALUES(?,?,?,?,?,?)", buf)
            conn.commit()
            buf = []
        total += len(t)
    if buf:
        conn.executemany("INSERT INTO ev VALUES(?,?,?,?,?,?)", buf)
        conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS ix_ev_time ON ev(time, src_user, src_computer)")
    conn.commit()
    conn.close()
    print(f"sorted sqlite built: {total:,} rows")


def _false_positive_keys(conn_path: Path, alerts_items: list, split_day: int) -> list:
    """Return the (src_user, src_computer, day) windows for false-positive alerts."""
    fps = []
    for at, u, s, hit, rt_t in alerts_items:
        if not hit:
            fps.append((u, s, at // DAY_SECONDS))
    return fps


def _count_negative_key_days(db_path: Path, split_day: int, rt_test: pd.DataFrame) -> int:
    """Count (src_user, src_computer, day) windows in the test period with NO red-team event.

    Used as the negative denominator for the documented FPR proxy. Red-team windows (positive)
    are the (user, src, day) combinations that actually carry a red-team event.
    """
    import sqlite3

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT DISTINCT src_user, src_computer, day FROM ev WHERE day >= ?", (split_day,)).fetchall()
    conn.close()
    # build the set of positive (user, src, day) windows from the test red-team
    positive = set()
    for _, r in rt_test.iterrows():
        positive.add((r["user"], r["src"], int(r["time"]) // DAY_SECONDS))
    negative = 0
    for u, s, d in rows:
        if (u, s, d) not in positive:
            negative += 1
    return negative


def _stream_and_eval(db_path: Path, rt: pd.DataFrame, split_day: int, delay_s: int,
                     failed_threshold: int, window_s: int, lateral_s: int,
                     scope_users: set[str], scope_computers: set[str]) -> dict:
    """Chronological pass maintaining per-key online state; emit alerts at first crossing.

    Temporal split: only TEST events (day >= split_day) are processed for detection; TRAIN
    events (day < split_day) are used only to fit the statistical baseline (not detection).
    Red-team matching is keyed by (src_user, src_computer). Recall uses only red-team events
    in the test period, and each red-team event can be matched at most once.
    """
    conn = sqlite3.connect(db_path)
    # Red-team for the test period, indexed by (src_user, src_computer).
    rt_test = rt[rt["time"] // DAY_SECONDS >= split_day].copy()
    rt_train = rt[rt["time"] // DAY_SECONDS < split_day]
    rt_by_key: dict[tuple[str, str], list] = {}
    for _, r in rt_test.iterrows():
        key = (r["user"], r["src"])
        rt_by_key.setdefault(key, []).append((int(r["time"]), r["dst"]))

    # Train-period statistics (per src_computer failure rate) for the statistical baseline.
    conn2 = sqlite3.connect(db_path)
    train_fail_rows = conn2.execute(
        "SELECT src_computer, COUNT(*) as n FROM ev WHERE day < ? AND status='failed' "
        "GROUP BY src_computer", (split_day,)).fetchall()
    conn2.close()
    train_fail = pd.DataFrame(train_fail_rows, columns=["src_computer", "n"])

    # Per-key online state (only for test-period events).
    state = {}
    # Per-USER recent success trail (for lateral movement: a user switching source computers).
    user_trail: dict[str, deque] = {}
    alerts = []  # (detector, alert_time, src_user, src_computer)

    cursor = conn.execute(
        "SELECT time, src_user, src_computer, dst_computer, status, day FROM ev "
        "ORDER BY time, src_user, src_computer")
    total = 0
    test_events = 0
    for time_v, u, s, dst, status, day in cursor:
        if day < split_day:
            continue  # train-period events are excluded from detection (temporal split)
        test_events += 1
        key = (u, s)
        st = state.setdefault(key, {
            "nfail": 0, "nsucc": 0, "last_event": None, "last_fail": None,
            "fail_deque": deque(),
            "bf_alerted": False, "bf_time": None,
            "burst_alerted": False, "burst_time": None,
            "saf_run": 0, "saf_alerted": False, "saf_time": None,
            "recent_succ": deque(), "lat_alerted": False, "lat_time": None,
        })
        if st["last_event"] is not None and time_v < st["last_event"]:
            continue
        st["last_event"] = time_v
        if status == "failed":
            st["nfail"] += 1
            st["last_fail"] = time_v
            if not st["bf_alerted"] and st["nfail"] >= failed_threshold:
                st["bf_alerted"] = True
                st["bf_time"] = time_v
                alerts.append(("bruteforce", time_v, u, s))
            dq = st["fail_deque"]
            dq.append(time_v)
            while dq and dq[0] < time_v - window_s:
                dq.popleft()
            if not st["burst_alerted"] and len(dq) >= failed_threshold:
                st["burst_alerted"] = True
                st["burst_time"] = time_v
                alerts.append(("burst", time_v, u, s))
            st["saf_run"] += 1
        else:  # success
            st["nsucc"] += 1
            if not st["saf_alerted"] and st["saf_run"] >= failed_threshold:
                st["saf_alerted"] = True
                st["saf_time"] = time_v
                alerts.append(("success_after_failures", time_v, u, s))
            st["saf_run"] = 0
            # lateral movement is per USER: a user succeeding from a different source
            # computer than a prior success within the window.
            trail = user_trail.setdefault(u, deque())
            prior_srcs = {x[1] for x in trail if x[1] != s}
            trail.append((time_v, s))
            while trail and trail[0][0] < time_v - lateral_s:
                trail.popleft()
            if not st["lat_alerted"] and prior_srcs:
                st["lat_alerted"] = True
                st["lat_time"] = time_v
                alerts.append(("lateral", time_v, u, s))
        total += 1
        if total % 20_000_000 == 0:
            print(f"  ... processed {total:,} test events", flush=True)
    conn.close()

    # ---- match alerts to red-team (a-priori, keyed by (user, src), no look-ahead) ----
    # Each red-team event is matched at most once; alerts BEFORE the ground-truth event are FPs.
    matched_rt = set()  # (rt_t, user, src)

    def match_alert(at, u, s):
        for (rt_t, rt_dst) in rt_by_key.get((u, s), []):
            if rt_t <= at <= rt_t + delay_s and (rt_t, u, s) not in matched_rt:
                return True, rt_t
            if at < rt_t - delay_s:
                # future events are too far; the closest matching one is later
                continue
        return False, None

    # Track per-detector alerts
    alerts_by_det: dict[str, list] = {}
    for det, at, u, s in alerts:
        hit, rt_t = match_alert(at, u, s)
        if hit:
            matched_rt.add((rt_t, u, s))
        alerts_by_det.setdefault(det, []).append((at, u, s, hit, rt_t))

    n_test_rt = len(rt_test)
    out = {}
    for det, items in alerts_by_det.items():
        tp = 0
        ttd = []
        fp = 0
        for at, u, s, hit, rt_t in items:
            if hit:
                tp += 1
                ttd.append(at - rt_t)  # >= 0 by construction (at >= rt_t)
            else:
                fp += 1
        n_al = len(items)
        precision = tp / n_al if n_al else 0.0
        recall = tp / n_test_rt if n_test_rt else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        # FPR requires a defined negative denominator: negative (key, day) windows in the test
        # period, i.e. keys/days with no red-team activity. We report alert-burden separately
        # and a documented PROXY FPR as false alerts per negative key-day (a proxy because it
        # uses key-day windows as the negative denominator, not a defined negative-event set).
        fp_keys = _false_positive_keys(conn_path=db_path, alerts_items=items, split_day=split_day)
        n_negative_key_days = _count_negative_key_days(db_path, split_day, rt_test)
        out[det] = {
            "n_alerts": n_al, "tp": tp, "fp": fp,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "median_ttd_s": float(np.median(ttd)) if ttd else None, "n_ttd": len(ttd),
            "recall_denominator_test_rt": int(n_test_rt),
            "alert_burden_alerts": n_al,
            "fpr_proxy_negative_key_days": round(fp / n_negative_key_days, 6) if n_negative_key_days else None,
            "fpr_proxy_definition": ("false alerts per negative (src_user, src_computer, day) "
                                     "window in the test period; a PROXY for FPR, not a true "
                                     "population false-positive rate"),
        }
    # Statistical baseline: per-src failure count in TEST vs train mean+k*sd.
    conn3 = sqlite3.connect(db_path)
    rows3 = conn3.execute(
        "SELECT src_computer, COUNT(*) as n, MIN(time) as first_fail FROM ev "
        "WHERE day >= ? AND status='failed' GROUP BY src_computer", (split_day,)).fetchall()
    conn3.close()
    test_fail = pd.DataFrame(rows3, columns=["src_computer", "n", "first_fail"])
    mu = float(train_fail["n"].mean()) if len(train_fail) else 0.0
    sd = float(train_fail["n"].std()) if len(train_fail) > 1 else 0.0
    thr = mu + 2.0 * sd
    stat_srcs = set(test_fail[test_fail["n"] >= thr]["src_computer"])
    out["stat_baseline"] = {
        "srcs_above_threshold": int(len(stat_srcs)),
        "threshold_mean_plus_2sd": round(thr, 4),
        "note": "count-based statistical diagnostic; matching requires a user key (see online detectors)",
    }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Online stateful Threat Hunting evaluation.")
    ap.add_argument("--input", default="data/lanl_eval_frame.parquet")
    ap.add_argument("--redteam", required=True)
    ap.add_argument("--split-day", type=int, default=15)
    ap.add_argument("--delay-minutes", type=int, default=30)
    ap.add_argument("--failed-threshold", type=int, default=5)
    ap.add_argument("--window-minutes", type=int, default=5)
    ap.add_argument("--lateral-hours", type=int, default=24)
    ap.add_argument("--output", default="results/lanl_online.json")
    args = ap.parse_args()

    start = time.time()
    rt = _redteam(Path(args.redteam))
    scope_users = set(rt["user"])
    scope_computers = set(rt["src"]) | set(rt["dst"])
    rt_test = rt[rt["time"] // DAY_SECONDS >= args.split_day]
    rt_train = rt[rt["time"] // DAY_SECONDS < args.split_day]
    db = Path("data/lanl_online.db")
    if db.exists():
        db.unlink()
    _build_sorted_sqlite(Path(args.input), db)
    results = _stream_and_eval(
        db, rt, args.split_day, args.delay_minutes * 60, args.failed_threshold,
        args.window_minutes * 60, args.lateral_hours * 3600, scope_users, scope_computers)

    payload = {
        "protocol": {
            "split": "temporal-by-day", "split_day": args.split_day,
            "delay_minutes": args.delay_minutes, "failed_threshold": args.failed_threshold,
            "window_minutes": args.window_minutes, "lateral_hours": args.lateral_hours,
            "redteam_total": int(len(rt)),
            "redteam_train": int(len(rt_train)),
            "redteam_test": int(len(rt_test)),
            "matching": "a-priori; alert matches next red-team event for the same key within "
                        "delay; no look-ahead; alert time = first threshold crossing",
            "threshold_selection": "fixed thresholds (documented); burst window / lateral hours "
                                   "are locked protocol parameters",
            "stateful": "online per-key state machines; bounded memory; chronological pass",
            "frame_sampling": "CONDITIONAL on the sampled eval frame (context + 5% background); "
                              "alert-burden and FPR-proxy are not population-wide unless "
                              "sampling weights applied",
        },
        "detectors": results,
        "elapsed_seconds": round(time.time() - start, 1),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote -> {out}")
    for det, r in results.items():
        print(f"  {det:24} P={r['precision']} R={r['recall']} F1={r['f1']} "
              f"alerts={r['n_alerts']} TTD={r['median_ttd_s']}s")


if __name__ == "__main__":
    main()