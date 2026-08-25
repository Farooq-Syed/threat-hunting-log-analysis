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

Events are processed in **chronological order** from a reusable time-sorted Parquet file. An
alert is emitted the first time a detector's threshold is crossed, and the crossing timestamp
is the alert time — so time-to-detection is the delay from the red-team event to that first
crossing, never the last failure. Matching is a-priori: an alert matches the next red-team
event for the same key within the delay window (no look-ahead).

The detector pass is memory-bounded: per-key state contains counts, short failure deques, and
the latest timestamp for each active user/source pair. The evaluator verifies chronological
order before detection. The locked 314M-row frame already preserves LANL time order, so it is
streamed directly without a database, index build, or duplicate sorted artifact.

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
import time
from collections import OrderedDict, deque
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
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


def _times_are_sorted(values: pa.ChunkedArray) -> bool:
    """Verify monotonic time without combining all Arrow chunks into another large array."""
    previous = None
    for chunk in values.chunks:
        arr = chunk.to_numpy(zero_copy_only=False)
        if len(arr) == 0:
            continue
        if previous is not None and arr[0] < previous:
            return False
        if len(arr) > 1 and np.any(np.diff(arr) < 0):
            return False
        previous = arr[-1]
    return True


def _parquet_is_chronological(path: Path, batch_size: int = 2_000_000) -> bool:
    """Check global monotonic time in a bounded-memory streaming pass."""
    previous = None
    pf = pq.ParquetFile(path)
    for batch in pf.iter_batches(batch_size=batch_size, columns=["time"]):
        arr = batch.column(0).to_numpy(zero_copy_only=False)
        if len(arr) == 0:
            continue
        if previous is not None and arr[0] < previous:
            return False
        if len(arr) > 1 and np.any(np.diff(arr) < 0):
            return False
        previous = arr[-1]
    return True


def _build_sorted_parquet(frame_path: Path, sorted_path: Path) -> None:
    """Create an atomically-written, chronologically sorted evaluation frame.

    The source frame is about 2 GB for the locked LANL run. Arrow handled the 314M-row
    time sort on the evaluation machine, whereas SQLite's row-wise load/index path did not.
    """
    columns = ["time", "src_user", "src_computer", "dst_computer", "status"]
    pf = pq.ParquetFile(frame_path)
    table = pf.read(columns=columns)
    status = pc.utf8_lower(pc.utf8_trim_whitespace(table["status"]))
    failed = pc.is_in(status, value_set=pa.array(["fail", "failed", "failure"]))
    normalized = pc.if_else(failed, pa.scalar("failed"), pa.scalar("success"))
    table = table.set_column(table.schema.get_field_index("status"), "status", normalized)

    order = pc.sort_indices(table, sort_keys=[
        ("time", "ascending"), ("src_user", "ascending"),
        ("src_computer", "ascending")])
    table = table.take(order)
    if not _times_are_sorted(table["time"]):
        raise RuntimeError("Arrow sort verification failed: time is not monotonic")

    sorted_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = sorted_path.with_suffix(sorted_path.suffix + ".partial")
    pq.write_table(table, temporary, compression="snappy", row_group_size=1_000_000)
    temporary.replace(sorted_path)
    marker = sorted_path.with_suffix(sorted_path.suffix + ".done")
    marker.write_text(json.dumps({
        "completed": True,
        "source": str(frame_path.resolve()),
        "source_size": frame_path.stat().st_size,
        "rows": table.num_rows,
        "minimum_time": int(pc.min(table["time"]).as_py()),
        "maximum_time": int(pc.max(table["time"]).as_py()),
        "sorted_by": ["time", "src_user", "src_computer"],
    }, indent=2), encoding="utf-8")
    print(f"sorted parquet built: {table.num_rows:,} rows -> {sorted_path}", flush=True)


def _prepare_chronological_parquet(frame_path: Path, sorted_path: Path,
                                   rebuild_sorted: bool = False) -> Path:
    """Reuse an already chronological source; otherwise build/reuse a sorted artifact."""
    if _parquet_is_chronological(frame_path):
        print(f"verified chronological source frame: {frame_path}", flush=True)
        return frame_path
    marker = sorted_path.with_suffix(sorted_path.suffix + ".done")
    if rebuild_sorted or not (sorted_path.exists() and marker.exists()):
        _build_sorted_parquet(frame_path, sorted_path)
    elif not _parquet_is_chronological(sorted_path):
        raise RuntimeError(f"completed sorted artifact is not chronological: {sorted_path}")
    else:
        print(f"reusing completed sorted frame: {sorted_path}", flush=True)
    return sorted_path


def _false_positive_keys(alerts_items: list) -> list:
    """Return the (src_user, src_computer, day) windows for false-positive alerts."""
    fps = []
    for at, u, s, hit, rt_t in alerts_items:
        if not hit:
            fps.append((u, s, at // DAY_SECONDS))
    return fps


def _count_negative_key_days(test_key_days: set[tuple[str, str, int]],
                             rt_test: pd.DataFrame) -> int:
    """Count (src_user, src_computer, day) windows in the test period with NO red-team event.

    Used as the negative denominator for the documented FPR proxy. Red-team windows (positive)
    are the (user, src, day) combinations that actually carry a red-team event.
    """
    positive = {(r["user"], r["src"], int(r["time"]) // DAY_SECONDS)
                for _, r in rt_test.iterrows()}
    return len(test_key_days - positive)


def _stream_and_eval(sorted_path: Path, rt: pd.DataFrame, split_day: int, delay_s: int,
                     failed_threshold: int, window_s: int, lateral_s: int) -> dict:
    """Chronological pass maintaining per-key online state; emit alerts at first crossing.

    Temporal split: only TEST events (day >= split_day) are processed for detection; TRAIN
    events (day < split_day) are used only to fit the statistical baseline (not detection).
    Red-team matching is keyed by (src_user, src_computer). Recall uses only red-team events
    in the test period, and each red-team event can be matched at most once.
    """
    # Red-team for the test period, indexed by (src_user, src_computer).
    rt_test = rt[rt["time"] // DAY_SECONDS >= split_day].copy()
    rt_train = rt[rt["time"] // DAY_SECONDS < split_day]
    rt_by_key: dict[tuple[str, str], list] = {}
    for _, r in rt_test.iterrows():
        key = (r["user"], r["src"])
        rt_by_key.setdefault(key, []).append((int(r["time"]), r["dst"]))

    for values in rt_by_key.values():
        values.sort()

    train_fail_counts: dict[str, int] = {}
    test_fail_counts: dict[str, int] = {}
    test_first_fail: dict[str, int] = {}
    test_key_days: set[tuple[str, str, int]] = set()

    # Per-key failure state; success-only keys do not allocate this structure.
    state: dict[tuple[str, str], dict] = {}
    bf_alerted: set[tuple[str, str]] = set()
    burst_alerted: set[tuple[str, str]] = set()
    saf_alerted: set[tuple[str, str]] = set()
    lateral_alerted: set[tuple[str, str]] = set()
    # Per-user active sources ordered by their latest timestamp. Updating a source moves it to
    # the end, so repeated successes do not create duplicate heap/deque entries. Memory is
    # bounded by distinct active (user, source) pairs rather than by event count.
    user_source_latest: dict[str, OrderedDict[str, int]] = {}
    alerts = []  # (detector, alert_time, src_user, src_computer)

    pf = pq.ParquetFile(sorted_path)
    previous_time = None
    test_events = 0
    columns = ["time", "src_user", "src_computer", "dst_computer", "status"]
    for batch in pf.iter_batches(batch_size=1_000_000, columns=columns):
        frame = batch.to_pandas()
        if len(frame) == 0:
            continue
        frame["status"] = frame["status"].str.strip().str.lower().map(
            lambda value: "failed" if value in ("fail", "failed", "failure") else "success")
        first_time = int(frame["time"].iloc[0])
        if previous_time is not None and first_time < previous_time:
            raise RuntimeError("sorted Parquet is not chronological")
        previous_time = int(frame["time"].iloc[-1])

        train = frame[(frame["time"] // DAY_SECONDS) < split_day]
        train_failed = train[train["status"] == "failed"]
        if len(train_failed):
            for src, count in train_failed.groupby("src_computer", sort=False).size().items():
                train_fail_counts[src] = train_fail_counts.get(src, 0) + int(count)

        test = frame[(frame["time"] // DAY_SECONDS) >= split_day]
        for time_v, u, s, dst, status in test.itertuples(index=False, name=None):
            time_v = int(time_v)
            day = time_v // DAY_SECONDS
            test_events += 1
            key = (u, s)
            test_key_days.add((u, s, day))
            if status == "failed":
                test_fail_counts[s] = test_fail_counts.get(s, 0) + 1
                test_first_fail.setdefault(s, time_v)
                st = state.setdefault(key, {"nfail": 0, "fail_deque": deque(), "saf_run": 0})
                st["nfail"] += 1
                if key not in bf_alerted and st["nfail"] >= failed_threshold:
                    bf_alerted.add(key)
                    alerts.append(("bruteforce", time_v, u, s))
                dq = st["fail_deque"]
                dq.append(time_v)
                while dq and dq[0] < time_v - window_s:
                    dq.popleft()
                if key not in burst_alerted and len(dq) >= failed_threshold:
                    burst_alerted.add(key)
                    alerts.append(("burst", time_v, u, s))
                st["saf_run"] += 1
            else:  # success
                st = state.get(key)
                if st is not None:
                    if key not in saf_alerted and st["saf_run"] >= failed_threshold:
                        saf_alerted.add(key)
                        alerts.append(("success_after_failures", time_v, u, s))
                    st["saf_run"] = 0

                latest = user_source_latest.setdefault(u, OrderedDict())
                cutoff = time_v - lateral_s
                while latest:
                    oldest_src, oldest_time = next(iter(latest.items()))
                    if oldest_time >= cutoff:
                        break
                    latest.popitem(last=False)
                has_other_source = len(latest) > (1 if s in latest else 0)
                if s in latest:
                    del latest[s]
                latest[s] = time_v
                if key not in lateral_alerted and has_other_source:
                    lateral_alerted.add(key)
                    alerts.append(("lateral", time_v, u, s))

            if test_events % 20_000_000 == 0:
                print(f"  ... processed {test_events:,} test events", flush=True)

    # ---- match alerts to red-team (a-priori, keyed by (user, src), no look-ahead) ----
    # Each red-team event is matched at most once PER DETECTOR. Different detectors are
    # evaluated independently and therefore may legitimately detect the same ground-truth event.
    def match_alert(at, u, s, matched_rt):
        for (rt_t, rt_dst) in rt_by_key.get((u, s), []):
            if rt_t <= at <= rt_t + delay_s and (rt_t, u, s) not in matched_rt:
                return True, rt_t
            if at < rt_t - delay_s:
                # future events are too far; the closest matching one is later
                continue
        return False, None

    # Track per-detector alerts
    detector_names = ("bruteforce", "burst", "success_after_failures", "lateral")
    alerts_by_det: dict[str, list] = {name: [] for name in detector_names}
    matched_by_detector: dict[str, set] = {name: set() for name in detector_names}
    for det, at, u, s in alerts:
        hit, rt_t = match_alert(at, u, s, matched_by_detector[det])
        if hit:
            matched_by_detector[det].add((rt_t, u, s))
        alerts_by_det.setdefault(det, []).append((at, u, s, hit, rt_t))

    n_test_rt = len(rt_test)
    test_days = {day for _, _, day in test_key_days}
    n_test_days = len(test_days)
    n_negative_key_days = _count_negative_key_days(test_key_days, rt_test)
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
        fp_key_days = set(_false_positive_keys(alerts_items=items))
        out[det] = {
            "n_alerts": n_al, "tp": tp, "fp": fp,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "median_ttd_s": float(np.median(ttd)) if ttd else None, "n_ttd": len(ttd),
            "recall_denominator_test_rt": int(n_test_rt),
            "test_event_count": int(test_events),
            "test_day_count": int(n_test_days),
            "alert_burden_alerts": n_al,
            "alerts_per_analyst_day": round(n_al / n_test_days, 4) if n_test_days else None,
            "false_alert_key_days": int(len(fp_key_days)),
            "negative_key_day_denominator": int(n_negative_key_days),
            "fpr_proxy_negative_key_days": (
                round(len(fp_key_days) / n_negative_key_days, 6)
                if n_negative_key_days else None),
            "fpr_proxy_definition": ("false alerts per negative (src_user, src_computer, day) "
                                     "window in the test period; a PROXY for FPR, not a true "
                                     "population false-positive rate"),
        }
    # Statistical baseline: per-src failure count in TEST vs train mean+k*sd.
    train_fail = pd.DataFrame(list(train_fail_counts.items()), columns=["src_computer", "n"])
    test_fail = pd.DataFrame([
        (src, count, test_first_fail[src]) for src, count in test_fail_counts.items()
    ], columns=["src_computer", "n", "first_fail"])
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
    ap.add_argument("--sorted-frame", default="data/lanl_frame_sorted.parquet",
                    help="Reusable time-sorted Parquet built from --input")
    ap.add_argument("--rebuild-sorted", action="store_true",
                    help="Rebuild the sorted Parquet even when a completed artifact exists")
    ap.add_argument("--output", default="results/lanl_online.json")
    args = ap.parse_args()

    start = time.time()
    rt = _redteam(Path(args.redteam))
    rt_test = rt[rt["time"] // DAY_SECONDS >= args.split_day]
    rt_train = rt[rt["time"] // DAY_SECONDS < args.split_day]
    frame = Path(args.input)
    sorted_frame = Path(args.sorted_frame)
    chronological_frame = _prepare_chronological_parquet(
        frame, sorted_frame, rebuild_sorted=args.rebuild_sorted)
    results = _stream_and_eval(
        chronological_frame, rt, args.split_day, args.delay_minutes * 60, args.failed_threshold,
        args.window_minutes * 60, args.lateral_hours * 3600)

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
            "stateful": "online per-key state machines; bounded detector state; chronological "
                        "stream from a reusable Arrow-sorted Parquet frame",
            "frame_sampling": "CONDITIONAL on the sampled eval frame (context + 5% background); "
                              "alert-burden and FPR-proxy are not population-wide unless "
                              "sampling weights applied",
        },
        "detectors": results,
        "elapsed_seconds": round(time.time() - start, 1),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    temporary = out.with_suffix(out.suffix + ".partial")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(out)
    print(f"Wrote -> {out}")
    for det, r in results.items():
        if "precision" in r:
            print(f"  {det:24} P={r['precision']} R={r['recall']} F1={r['f1']} "
                  f"alerts={r['n_alerts']} TTD={r['median_ttd_s']}s")
        else:
            print(f"  {det:24} {r}")


if __name__ == "__main__":
    main()
