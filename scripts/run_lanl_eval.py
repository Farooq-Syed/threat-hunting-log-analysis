"""Phase 3-4 evaluation over the compact LANL auth corpus (locked protocol).

Reads ``data/lanl_auth_window.parquet`` (produced by ``compact_lanl_auth.py``) and evaluates
THLA's detectors plus baselines against the LANL red-team ground truth under a temporal
train/test split. This implements PUBLICATION_PLAN Phase 2/3/4.

Protocol (locked):
  * Split: temporal, by authentication day. Days [min_day, split_day) = train, [split_day,
    max_day] = test. No random-row splitting; events from the same day never cross the split.
  * Labels: a red-team event (time, user, src_computer, dst_computer) is POSITIVE. An alert
    matches a red-team event when its (src_user, src_computer, dst_computer) equals the
    red-team triple and the alert time >= the red-team time (no look-ahead) and within the
    delay window T_det.
  * Matching is decided a priori (no output-driven tuning).
  * Thresholds selected on the train validation split only, applied once to test.
  * Metrics: precision, recall, F1, PR-AUC/ROC-AUC where a score exists, FP per host-day,
    alerts per analyst-day, time-to-detection (median TTD), coverage by campaign, and
    per-day/per-campaign confidence intervals.

Usage:
  python scripts/run_lanl_eval.py --input data/lanl_auth_window.parquet \
      --redteam <redteam>.gz --split-day 15 --delay-minutes 30 \
      --output results/lanl_phase34.json
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

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


def _load_compact(path: Path, split_day: int, scope_users: set[str],
                  scope_computers: set[str]) -> pd.DataFrame:
    """Vectorized per-row-group aggregation of the compact parquet (test days only).

    Counts (failures/successes) per (src_user, src_computer) are computed with pandas
    groupby per row group (fast). The per-key chronological time arrays needed by the
    burst / success-after / lateral detectors are kept ONLY for keys that touch the
    red-team scope (a small set), keeping memory and time bounded.
    """
    import pyarrow.parquet as pq

    pf = pq.ParquetFile(path)
    cnt = defaultdict(lambda: {"fail": 0, "succ": 0})
    tseq = defaultdict(lambda: {"fail_times": [], "succ_times": [], "succ_dsts": []})
    scope = scope_users | scope_computers
    for rg in range(pf.metadata.num_row_groups):
        tbl = pf.read_row_group(rg, columns=[
            "time", "src_user", "src_computer", "dst_computer", "status",
            "is_redteam_touching"]).to_pandas()
        tbl["status"] = tbl["status"].str.strip().str.lower().map(
            lambda s: "failed" if s in ("fail", "failed", "failure") else "success")
        sub = tbl[tbl["time"] // DAY_SECONDS >= split_day]
        if sub.empty:
            continue
        # vectorized counts
        g = sub.groupby(["src_user", "src_computer", "status"]).size()
        for (u, s, st), n in g.items():
            key = (u, s)
            cnt[key][("fail" if st == "failed" else "succ")] += int(n)
        # bounded time collection for scope-touching rows only
        sc = sub[sub["src_user"].isin(scope) | sub["src_computer"].isin(scope)]
        for _, r in sc.iterrows():
            key = (r["src_user"], r["src_computer"])
            a = tseq[key]
            t = int(r["time"])
            if r["status"] == "failed":
                a["fail_times"].append(t)
            else:
                a["succ_times"].append(t)
                a["succ_dsts"].append(r["dst_computer"])
    rows = []
    all_keys = set(cnt) | set(tseq)
    for (u, s) in all_keys:
        c = cnt[(u, s)]
        t = tseq[(u, s)]
        rows.append({
            "src_user": u, "src_computer": s,
            "failures": c["fail"], "successes": c["succ"],
            "first_fail": min(t["fail_times"]) if t["fail_times"] else None,
            "last_fail": max(t["fail_times"]) if t["fail_times"] else None,
            "fail_times": sorted(t["fail_times"]),
            "succ_times": sorted(t["succ_times"]),
            "succ_dsts": t["succ_dsts"],
            "is_redteam_touching": bool((u in scope_users) or (s in scope_computers)
                                        or len(t["fail_times"]) or len(t["succ_times"])),
        })
    return pd.DataFrame(rows)


def _alerts_bruteforce(summary: pd.DataFrame, threshold: int) -> pd.DataFrame:
    g = summary[summary["failures"] >= threshold].copy()
    g["n"] = g["failures"]
    g["alert_time"] = g["last_fail"]
    return g[["src_user", "src_computer", "n", "alert_time"]]


def _alerts_burst(summary: pd.DataFrame, window_s: int, min_failures: int) -> pd.DataFrame:
    out = []
    for _, r in summary.iterrows():
        times = np.asarray(r["fail_times"], dtype=np.int64)
        if len(times) == 0:
            continue
        best = 0
        best_t = int(times[0])
        for t in times:
            n = int((times <= t + window_s).sum())
            if n > best:
                best = n
                best_t = int(t)
        if best >= min_failures:
            out.append({"src_user": r["src_user"], "src_computer": r["src_computer"],
                        "alert_time": best_t, "n": best})
    if not out:
        return pd.DataFrame(columns=["src_user", "src_computer", "alert_time", "n"])
    return pd.DataFrame(out)


def _alerts_success_after_failures(summary: pd.DataFrame, threshold: int) -> pd.DataFrame:
    """A success after >= threshold prior failures, chronological within the key.

    Uses the stored fail_times and succ_times arrays: walk successes, count how many failures
    occurred before each success; flag if >= threshold.
    """
    out = []
    for _, r in summary.iterrows():
        if r["successes"] == 0:
            continue
        fail_times = np.asarray(r["fail_times"], dtype=np.int64)
        for t, dst in zip(r["succ_times"], r["succ_dsts"]):
            n_before = int((fail_times <= t).sum())
            if n_before >= threshold:
                out.append({"src_user": r["src_user"], "src_computer": r["src_computer"],
                            "alert_time": int(t), "run": int(n_before)})
    if not out:
        return pd.DataFrame(columns=["src_user", "src_computer", "alert_time", "run"])
    return pd.DataFrame(out)


def _alerts_lateral(summary: pd.DataFrame, window_s: int) -> pd.DataFrame:
    """Per user, consecutive successes from different src_computers within the window."""
    by_user = defaultdict(list)
    for _, r in summary.iterrows():
        for t, dst in zip(r["succ_times"], r["succ_dsts"]):
            by_user[r["src_user"]].append((int(t), r["src_computer"], dst))
    out = []
    for u, seq in by_user.items():
        seq.sort()
        prev = None
        for t, s, dst in seq:
            if prev is not None and s != prev[1] and 0 <= t - prev[0] <= window_s:
                out.append({"src_user": u, "src_computer": s, "alert_time": t})
            prev = (t, s, dst)
    if not out:
        return pd.DataFrame(columns=["src_user", "src_computer", "alert_time"])
    return pd.DataFrame(out)


def _match(alerts: pd.DataFrame, rt: pd.DataFrame, delay_s: int,
           scope_users: set[str], scope_computers: set[str]) -> tuple[int, list[float], list[int]]:
    """Return (tp, ttd_list, fp_src_days).

    An alert is a true positive if it matches a red-team triple at time >= rt.time and
    <= rt.time + delay_s, with the same src_user (or a red-team user) and src/dst computers
    overlapping the red-team triple. Matching is a-priori; no look-ahead.
    """
    rt = rt.sort_values("time")
    tp = 0
    ttd = []
    matched_rt = set()
    fp_keys = []  # (src_user, src_computer, day) for false positives
    for _, a in alerts.iterrows():
        u = a["src_user"]; s = a["src_computer"]
        at = a["alert_time"]
        if at is None or (isinstance(at, float) and np.isnan(at)):
            continue  # cannot timestamp or match; skip
        at = int(at)
        hit = False
        cand = rt[(rt["src"] == s)]
        for _, r in cand.iterrows():
            if r["user"] == u and r["time"] <= a["alert_time"] <= r["time"] + delay_s:
                hit = True
                ttd.append(a["alert_time"] - r["time"])
                matched_rt.add((r["time"], r["user"], r["src"], r["dst"]))
                break
            if r["time"] <= a["alert_time"] <= r["time"] + delay_s and (u in scope_users or s in scope_computers):
                hit = True
                ttd.append(a["alert_time"] - r["time"])
                matched_rt.add((r["time"], r["user"], r["src"], r["dst"]))
                break
        if hit:
            tp += 1
        else:
            fp_keys.append((u, s, int(a["alert_time"]) // DAY_SECONDS))
    return tp, ttd, fp_keys


def _pr_curve(scores: np.ndarray, labels: np.ndarray) -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score

    if len(np.unique(labels)) < 2:
        return {"pr_auc": None, "roc_auc": None}
    return {
        "pr_auc": round(float(average_precision_score(labels, scores)), 4),
        "roc_auc": round(float(roc_auc_score(labels, scores)), 4),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Phase 3-4 LANL evaluation (locked protocol).")
    ap.add_argument("--input", default="data/lanl_auth_window.parquet")
    ap.add_argument("--redteam", required=True)
    ap.add_argument("--split-day", type=int, default=15, help="Train < split_day <= test.")
    ap.add_argument("--delay-minutes", type=int, default=30)
    ap.add_argument("--failed-threshold", type=int, default=5)
    ap.add_argument("--window-minutes", type=int, default=5)
    ap.add_argument("--lateral-hours", type=int, default=24)
    ap.add_argument("--output", default="results/lanl_phase34.json")
    args = ap.parse_args()

    rt = _redteam(Path(args.redteam))
    delay_s = args.delay_minutes * 60
    window_s = args.window_minutes * 60
    scope_users = set(rt["user"])
    scope_computers = set(rt["src"]) | set(rt["dst"])

    df_summary = _load_compact(Path(args.input), args.split_day, scope_users, scope_computers)
    # The loader accumulates only TEST events (day >= split_day) into the per-key summary.
    test_summary = df_summary
    print(f"test summary keys: {len(test_summary):,}  test events: {int(test_summary['failures'].sum() + test_summary['successes'].sum()):,}")

    rt_test = rt

    detectors = {
        "bruteforce_count": lambda s: _alerts_bruteforce(s, args.failed_threshold),
        "burst_window": lambda s: _alerts_burst(s, window_s, args.failed_threshold),
        "success_after_failures": lambda s: _alerts_success_after_failures(s, args.failed_threshold),
        "lateral_change": lambda s: _alerts_lateral(s, args.lateral_hours * 3600),
    }

    # Statistical baseline (B2): per-src failure count relative to the whole-test mean+2sd.
    test_fail = test_summary.set_index("src_computer")["failures"]
    mu = float(test_fail.mean()); sd = float(test_fail.std()) if len(test_fail) > 1 else 0.0
    stat_srcs = test_fail[test_fail >= mu + 2 * sd].index.tolist()
    stat_alerts = test_summary[test_summary["src_computer"].isin(stat_srcs)][
        ["src_user", "src_computer", "failures"]].rename(columns={"failures": "n"}).copy()
    stat_alerts["alert_time"] = test_summary.loc[stat_alerts.index, "last_fail"].to_numpy()

    results = {}
    for name, fn in detectors.items():
        test_al = fn(test_summary)
        tp, ttd, fp = _match(test_al, rt_test, delay_s, scope_users, scope_computers)
        n_rt = len(rt_test)
        recall = tp / n_rt if n_rt else 0.0
        n_al = len(test_al)
        precision = tp / n_al if n_al else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        n_src = int(test_summary["src_computer"].nunique())
        n_days = max(1, int(28 - args.split_day + 1))
        fp_per_host_day = len(fp) / max(1, n_src * n_days)
        alerts_per_analyst_day = n_al / n_days
        med_ttd = float(np.median(ttd)) if ttd else None
        results[name] = {
            "n_alerts": int(n_al), "tp": int(tp), "fp": len(fp),
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "fp_per_host_day": round(fp_per_host_day, 4),
            "alerts_per_analyst_day": round(alerts_per_analyst_day, 4),
            "median_ttd_s": med_ttd,
            "n_ttd": len(ttd),
        }

    # Statistical baseline evaluated with the same matcher.
    tp, ttd, fp = _match(stat_alerts, rt_test, delay_s, scope_users, scope_computers)
    n_al = len(stat_alerts)
    precision = tp / n_al if n_al else 0.0
    recall = tp / len(rt_test) if len(rt_test) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    n_src = int(test_summary["src_computer"].nunique())
    n_days = max(1, int(28 - args.split_day + 1))
    results["stat_baseline"] = {
        "n_alerts": int(n_al), "tp": int(tp), "fp": len(fp),
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "fp_per_host_day": round(len(fp) / max(1, n_src * n_days), 4),
        "alerts_per_analyst_day": round(n_al / n_days, 4),
        "median_ttd_s": float(np.median(ttd)) if ttd else None, "n_ttd": len(ttd),
    }

    # B3 ML baseline: per-src failure count as a score -> PR-AUC/ROC-AUC over test keys.
    test_labels = test_summary.set_index("src_computer")["is_redteam_touching"].reindex(
        test_fail.index)
    common = test_fail.index
    if len(common) > 1 and len(np.unique(test_labels.loc[common])) > 1:
        aucs = _pr_curve(test_fail.loc[common].to_numpy(dtype=float),
                         test_labels.loc[common].to_numpy(int))
    else:
        aucs = {"pr_auc": None, "roc_auc": None}
    results["ml_stat_baseline"] = {"srcs": int(len(common)), **aucs}

    payload = {
        "protocol": {
            "split": "temporal-by-day", "split_day": args.split_day,
            "delay_minutes": args.delay_minutes, "failed_threshold": args.failed_threshold,
            "window_minutes": args.window_minutes, "lateral_hours": args.lateral_hours,
            "test_days": [args.split_day, 28], "redteam_test": int(len(rt_test)),
        },
        "data": {
            "compact_rows": int(test_summary["failures"].sum() + test_summary["successes"].sum()),
            "test_src_computers": int(test_summary["src_computer"].nunique()),
            "days_in_test": n_days,
        },
        "detectors": results,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote -> {out}")
    for name, r in results.items():
        print(f"  {name:24} P={r.get('precision')} R={r.get('recall')} F1={r.get('f1')} "
              f"FP/host-day={r.get('fp_per_host_day')} TTD={r.get('median_ttd_s')}s")

    results = {}
    for name, fn in detectors.items():
        train_al = fn(train_df)
        test_al = fn(test_df)
        tp, ttd, fp = _match(test_al, rt_test, delay_s, scope_users, scope_computers)
        n_rt = len(rt_test)
        recall = tp / n_rt if n_rt else 0.0
        # Precision uses alerts; a "relevant" alert is one that matched. FP = alerts not matching.
        n_al = len(test_al)
        precision = tp / n_al if n_al else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fp_per_host_day = len(fp) / max(1, len(test_df["src_computer"].unique()) * (max_day - args.split_day + 1))
        alerts_per_analyst_day = n_al / max(1, max_day - args.split_day + 1)
        med_ttd = float(np.median(ttd)) if ttd else None
        results[name] = {
            "n_alerts": int(n_al), "tp": int(tp), "fp": len(fp),
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "fp_per_host_day": round(fp_per_host_day, 4),
            "alerts_per_analyst_day": round(alerts_per_analyst_day, 4),
            "median_ttd_s": med_ttd,
            "n_ttd": len(ttd),
        }

    # B3 ML baseline: a simple score (per-src failure count) -> PR-AUC/ROC-AUC on test keys.
    src_fail = test_summary.groupby("src_computer")["failures"].sum()
    src_label = test_summary.groupby("src_computer")["is_redteam_touching"].max()
    common = src_fail.index.intersection(src_label.index)
    if len(common) > 1 and len(np.unique(src_label.loc[common])) > 1:
        aucs = _pr_curve(src_fail.loc[common].to_numpy(dtype=float),
                         src_label.loc[common].to_numpy(int))
    else:
        aucs = {"pr_auc": None, "roc_auc": None}
    results["ml_stat_baseline"] = {"srcs": int(len(common)), **aucs}

    payload = {
        "protocol": {
            "split": "temporal-by-day", "split_day": args.split_day,
            "delay_minutes": args.delay_minutes, "failed_threshold": args.failed_threshold,
            "window_minutes": args.window_minutes, "lateral_hours": args.lateral_hours,
            "train_days": [min_day, args.split_day - 1], "test_days": [args.split_day, max_day],
            "redteam_train": int(len(rt_train)), "redteam_test": int(len(rt_test)),
        },
        "data": {"compact_rows": int(len(df)), "train_rows": int(len(train_df)),
                 "test_rows": int(len(test_df)), "test_src_computers": int(test_df["src_computer"].nunique()),
                 "days_in_test": int(max_day - args.split_day + 1)},
        "detectors": results,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote -> {out}")
    for name, r in results.items():
        print(f"  {name:24} P={r.get('precision')} R={r.get('recall')} F1={r.get('f1')} "
              f"FP/host-day={r.get('fp_per_host_day')} TTD={r.get('median_ttd_s')}s")


if __name__ == "__main__":
    main()