"""Streaming Phase 3-4 evaluator over the sampled LANL eval frame.

Memory-safe: reads the (up to ~315M-row) eval frame in small batches and accumulates
per-(src_user, src_computer) state in SQLite (counts + first/last failure time). Detector
matching and all metrics are computed on the accumulated per-key aggregates, never on the
full frame in RAM. This is the implementation-level streaming evaluator required when the
frame is too large for an in-memory pass.

Scope of this run (documented):
  * count-based detector (brute-force: failures >= threshold per key)
  * statistical baseline (per-src failure count vs train mean + k*sd)
  * ML baseline (per-src failure count as a score -> PR-AUC / ROC-AUC)
  * operational metrics: precision, recall, F1, FP per host-day, alerts per analyst-day,
    median time-to-detection, detection coverage, per-key PR/ROC where applicable
  * time-sequence detectors (burst / success-after-failure / lateral) require per-event
    chronological state and are NOT included in this run; they are flagged as needing the
    full streaming temporal state (future work on the same code path).

Protocol: temporal split by day (train < split_day <= test). Thresholds are chosen on the
TRAIN portion only (the train mean/sd are fit on train-day events). Stateful features are
reset per fold; test events are never used to fit train statistics. Alert-burden estimates
are CONDITIONAL on the sampled eval frame (per PUBLICATION_PLAN Phase 2).

Usage:
  python scripts/stream_lanl_eval.py --input data/lanl_eval_frame.parquet \
      --redteam <redteam>.gz --split-day 15 --delay-minutes 30 \
      --output results/lanl_phase34.json
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sqlite3
import time
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


def _accumulate(frame_path: Path, split_day: int, db_path: Path) -> dict:
    """Stream the frame in batches into SQLite per-key aggregates. Returns row counts."""
    import sqlite3 as sq

    conn = sq.connect(db_path)
    conn.execute("DROP TABLE IF EXISTS keys")
    conn.execute("CREATE TABLE keys (src_user TEXT, src_computer TEXT, day INT, "
                 "nfail INT, nsucc INT, minf INT, maxf INT, PRIMARY KEY(src_user, src_computer, day))")
    pf = pq.ParquetFile(frame_path)
    total = 0
    train_rows = 0
    test_rows = 0
    n_train_rt = 0
    n_test_rt = 0
    for batch in pf.iter_batches(batch_size=1_000_000, columns=[
            "time", "src_user", "src_computer", "status", "is_redteam_touching"]):
        t = batch.to_pandas()
        t["status"] = t["status"].str.strip().str.lower().map(
            lambda s: "failed" if s in ("fail", "failed", "failure") else "success")
        t["day"] = (t["time"] // DAY_SECONDS).astype(int)
        total += len(t)
        test_mask = t["day"] >= split_day
        train_rows += int((~test_mask).sum())
        test_rows += int(test_mask.sum())
        n_train_rt += int((~test_mask & t["is_redteam_touching"]).sum())
        n_test_rt += int((test_mask & t["is_redteam_touching"]).sum())
        # aggregate per (key, day, status) in this batch (vectorized)
        g = t.groupby(["src_user", "src_computer", "day", "status"]).agg(
            n=("time", "count"), lo=("time", "min"), hi=("time", "max")).reset_index()
        # split into two bulk upserts: failures and successes
        fail = g[g["status"] == "failed"]
        succ = g[g["status"] == "success"]
        conn.executemany(
            "INSERT INTO keys(src_user,src_computer,day,nfail,nsucc,minf,maxf) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(src_user,src_computer,day) DO UPDATE SET "
            "nfail=nfail+excluded.nfail, nsucc=nsucc+excluded.nsucc, "
            "minf=CASE WHEN excluded.minf IS NOT NULL AND (keys.minf IS NULL OR excluded.minf<keys.minf) "
            "      THEN excluded.minf ELSE keys.minf END, "
            "maxf=CASE WHEN excluded.maxf IS NOT NULL AND (keys.maxf IS NULL OR excluded.maxf>keys.maxf) "
            "      THEN excluded.maxf ELSE keys.maxf END",
            list(fail[["src_user", "src_computer", "day", "n", "n", "lo", "hi"]].itertuples(index=False, name=None)))
        conn.executemany(
            "INSERT INTO keys(src_user,src_computer,day,nfail,nsucc,minf,maxf) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(src_user,src_computer,day) DO UPDATE SET "
            "nfail=nfail+excluded.nfail, nsucc=nsucc+excluded.nsucc",
            list(succ[["src_user", "src_computer", "day", "n", "n", "n", "n"]].itertuples(index=False, name=None)))
        conn.commit()
    conn.close()
    return {"total": total, "train_rows": train_rows, "test_rows": test_rows,
            "n_train_rt": n_train_rt, "n_test_rt": n_test_rt}


def _load_keys(db_path: Path, split_day: int) -> tuple[pd.DataFrame, dict]:
    """Load per-key aggregates split by day. Returns (train_summary, test_summary)."""
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT src_user, src_computer, day, nfail, nsucc, minf, maxf FROM keys", conn)
    conn.close()
    train = df[df["day"] < split_day].groupby(["src_user", "src_computer"], as_index=False).agg(
        nfail=("nfail", "sum"), nsucc=("nsucc", "sum"),
        minf=("minf", "min"), maxf=("maxf", "max"))
    test = df[df["day"] >= split_day].groupby(["src_user", "src_computer"], as_index=False).agg(
        nfail=("nfail", "sum"), nsucc=("nsucc", "sum"),
        minf=("minf", "min"), maxf=("maxf", "max"))
    return train, test


def _match_count(alerts: pd.DataFrame, rt: pd.DataFrame, delay_s: int,
                 scope_users: set[str], scope_computers: set[str]) -> dict:
    """Match count-based alerts (with alert_time) to red-team; no look-ahead."""
    rt = rt.sort_values("time")
    tp = 0
    ttd = []
    fp_keys = []
    for _, a in alerts.iterrows():
        u = a["src_user"]
        s = a["src_computer"]
        at = a["alert_time"]
        if at is None or (isinstance(at, float) and np.isnan(at)):
            continue
        at = int(at)
        hit = False
        for _, r in rt[rt["src"] == s].iterrows():
            if r["time"] <= at <= r["time"] + delay_s and (r["user"] == u or u in scope_users or s in scope_computers):
                hit = True
                ttd.append(at - int(r["time"]))
                break
        if hit:
            tp += 1
        else:
            fp_keys.append((u, s, at // DAY_SECONDS))
    return {"tp": tp, "ttd": ttd, "fp": fp_keys}


def main() -> None:
    ap = argparse.ArgumentParser(description="Streaming Phase 3-4 LANL evaluation.")
    ap.add_argument("--input", default="data/lanl_eval_frame.parquet")
    ap.add_argument("--redteam", required=True)
    ap.add_argument("--split-day", type=int, default=15)
    ap.add_argument("--delay-minutes", type=int, default=30)
    ap.add_argument("--failed-threshold", type=int, default=5)
    ap.add_argument("--sd-k", type=float, default=2.0, help="Statistical baseline: mean + k*sd.")
    ap.add_argument("--output", default="results/lanl_phase34.json")
    args = ap.parse_args()

    start = time.time()
    db = Path("data/lanl_keys_stream.db")
    if db.exists():
        db.unlink()
    rows = _accumulate(Path(args.input), args.split_day, db)
    train_summary, test_summary = _load_keys(db, args.split_day)
    rt = _redteam(Path(args.redteam))
    rt["day"] = rt["time"] // DAY_SECONDS
    rt_train = rt[rt["day"] < args.split_day]
    rt_test = rt[rt["day"] >= args.split_day]
    scope_users = set(rt["user"])
    scope_computers = set(rt["src"]) | set(rt["dst"])
    delay_s = args.delay_minutes * 60

    print(f"accumulate: {rows['total']:,} events; train {rows['train_rows']:,} / test {rows['test_rows']:,}")
    print(f"keys: train {len(train_summary):,} test {len(test_summary):,} ; "
          f"red-team train {rows['n_train_rt']:,} test {rows['n_test_rt']:,}")

    # ---- count-based detector (brute-force): train threshold fixed, applied to test ----
    test_bf = test_summary[test_summary["nfail"] >= args.failed_threshold].copy()
    test_bf["alert_time"] = test_bf["maxf"]
    bf = _match_count(test_bf, rt_test, delay_s, scope_users, scope_computers)
    n_al = len(test_bf)
    n_rt = len(rt_test)
    precision = bf["tp"] / n_al if n_al else 0.0
    recall = bf["tp"] / n_rt if n_rt else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    n_hosts = int(test_summary["src_computer"].nunique())
    n_days = max(1, int(test_summary["day"].max()) - args.split_day + 1)
    fp = bf["fp"]
    fp_per_host_day = len(fp) / max(1, n_hosts * n_days)
    alerts_per_analyst_day = n_al / n_days
    med_ttd = float(np.median(bf["ttd"])) if bf["ttd"] else None
    detectors = {
        "bruteforce_count": {
            "n_alerts": int(n_al), "tp": int(bf["tp"]), "fp": len(fp),
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "fp_per_host_day": round(fp_per_host_day, 4),
            "alerts_per_analyst_day": round(alerts_per_analyst_day, 4),
            "median_ttd_s": med_ttd, "n_ttd": len(bf["ttd"]),
            "coverage_rt": round(bf["tp"] / n_rt, 4) if n_rt else 0.0,
        }
    }

    # ---- statistical baseline: train mean+sd on per-src failure counts, applied to test ----
    train_fail_per_src = train_summary.groupby("src_computer")["nfail"].sum()
    mu = float(train_fail_per_src.mean()) if len(train_fail_per_src) else 0.0
    sd = float(train_fail_per_src.std()) if len(train_fail_per_src) > 1 else 0.0
    thr = mu + args.sd_k * sd
    test_fail_per_src = test_summary.groupby("src_computer")["nfail"].sum()
    stat_srcs = set(test_fail_per_src[test_fail_per_src >= thr].index)
    stat_al = test_summary[test_summary["src_computer"].isin(stat_srcs)].copy()
    stat_al["alert_time"] = stat_al["maxf"]
    st = _match_count(stat_al, rt_test, delay_s, scope_users, scope_computers)
    n_al2 = len(stat_al)
    precision2 = st["tp"] / n_al2 if n_al2 else 0.0
    recall2 = st["tp"] / n_rt if n_rt else 0.0
    f12 = 2 * precision2 * recall2 / (precision2 + recall2) if precision2 + recall2 else 0.0
    detectors["stat_baseline"] = {
        "n_alerts": int(n_al2), "tp": int(st["tp"]), "fp": len(st["fp"]),
        "precision": round(precision2, 4), "recall": round(recall2, 4), "f1": round(f12, 4),
        "fp_per_host_day": round(len(st["fp"]) / max(1, n_hosts * n_days), 4),
        "alerts_per_analyst_day": round(n_al2 / n_days, 4),
        "median_ttd_s": float(np.median(st["ttd"])) if st["ttd"] else None,
        "n_ttd": len(st["ttd"]), "threshold_mean_plus_k_sd": round(thr, 4),
    }

    # ---- ML baseline: per-src failure count as score -> PR-AUC / ROC-AUC on test keys ----
    src_fail = test_summary.groupby("src_computer")["nfail"].sum()
    src_rt = test_summary.groupby("src_computer")["is_redteam_touching"].max() if "is_redteam_touching" in test_summary else None
    # is_redteam_touching is a frame column; derive from key membership
    src_rt = pd.Series([(s in scope_computers) for s in src_fail.index], index=src_fail.index)
    common = src_fail.index
    if len(common) > 1 and len(np.unique(src_rt.loc[common])) > 1:
        from sklearn.metrics import average_precision_score, roc_auc_score
        detectors["ml_stat_baseline"] = {
            "pr_auc": round(float(average_precision_score(src_rt.loc[common].astype(int),
                                                          src_fail.loc[common].to_numpy(dtype=float))), 4),
            "roc_auc": round(float(roc_auc_score(src_rt.loc[common].astype(int),
                                                 src_fail.loc[common].to_numpy(dtype=float))), 4),
            "srcs": int(len(common)),
        }
    else:
        detectors["ml_stat_baseline"] = {"pr_auc": None, "roc_auc": None, "srcs": int(len(common))}

    payload = {
        "protocol": {
            "split": "temporal-by-day", "split_day": args.split_day,
            "delay_minutes": args.delay_minutes, "failed_threshold": args.failed_threshold,
            "sd_k": args.sd_k, "test_days": [args.split_day, int(test_summary["day"].max())],
            "redteam_train": int(len(rt_train)), "redteam_test": int(len(rt_test)),
            "threshold_selection": "train-only (failed-threshold fixed; stat mean+sd fit on train days)",
            "stateful_reset": "streaming per-fold; test events never used to fit train statistics",
            "frame_sampling": ("CONDITIONAL on the sampled eval frame; alert-burden is not "
                               "population-wide unless sampling weights are applied"),
            "not_included": ("burst / success-after-failure / lateral time-sequence detectors "
                             "require full chronological per-key state (future streaming work)"),
        },
        "data": {
            "total_events": int(rows["total"]),
            "train_events": int(rows["train_rows"]), "test_events": int(rows["test_rows"]),
            "test_src_computers": n_hosts, "test_days": n_days,
            "redteam_train_touching": int(rows["n_train_rt"]),
            "redteam_test_touching": int(rows["n_test_rt"]),
            "eval_frame_rows": 314683765,  # from the verified eval-frame manifest
        },
        "detectors": detectors,
        "elapsed_seconds": round(time.time() - start, 1),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote -> {out}")
    for name, r in detectors.items():
        print(f"  {name:22} P={r.get('precision')} R={r.get('recall')} F1={r.get('f1')} "
              f"FP/host-day={r.get('fp_per_host_day')} TTD={r.get('median_ttd_s')}s")


if __name__ == "__main__":
    main()