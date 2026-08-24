"""Regression tests for the online stateful LANL evaluator.

Covers the reviewer-required correctness properties:
  * a pre-split (train-period) event cannot affect test metrics;
  * an alert from a different user on the same source computer does not match;
  * training-period red-team events are excluded from the test recall denominator;
  * each red-team event can be matched at most once (no reuse);
  * pre-attack alerts (before the ground-truth event) remain false positives;
  * time-to-detection is always non-negative.
"""

import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from scripts.online_lanl_eval import _build_sorted_sqlite, _stream_and_eval, _redteam  # noqa: E402

DAY = 86400
BASE = 150000  # day 1


def _write_frame(rows, path):
    pd.DataFrame(rows).to_parquet(path)
    return path


def _run(rows, redteam_rows, split_day=2, **kw):
    import tempfile as _tf

    with _tf.TemporaryDirectory() as d:
        d = Path(d)
        f = _write_frame(rows, d / "f.parquet")
        rt_path = d / "redteam.txt"
        rt_path.write_text("\n".join(redteam_rows) + "\n")
        db = d / "db.sqlite"
        _build_sorted_sqlite(f, db)
        rt = _redteam(rt_path)
        res = _stream_and_eval(
            db, rt, split_day, kw.get("delay_s", 1800),
            kw.get("failed_threshold", 5), kw.get("window_s", 60),
            kw.get("lateral_s", 86400), set(rt["user"]), set(rt["src"]) | set(rt["dst"]))
    return res


def test_pre_split_event_does_not_affect_test():
    # Train-period failures (day < split_day=2) must not produce test alerts.
    rows = []
    for i in range(6):
        rows.append({"time": BASE + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})  # day 1 (train)
    # one test-period success (day >= 2)
    rows.append({"time": BASE + 2 * DAY, "src_user": "U1@DOM1", "src_computer": "C1",
                 "dst_computer": "C2", "status": "success"})
    res = _run(rows, [f"{BASE + 2 * DAY + 50},U1@DOM1,C1,C2"])
    # No brute-force alert because the 6 failures are all in the train period.
    bf = res.get("bruteforce", {})
    assert bf.get("n_alerts", 0) == 0, "train-period failures must not create test alerts"


def test_different_user_same_src_does_not_match():
    # Red-team is for U1@DOM1/C1; an alert from U2@DOM1 on C1 must NOT match.
    rows = []
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U2@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    res = _run(rows, [f"{BASE + 2 * DAY + 20},U1@DOM1,C1,C2"])
    bf = res["bruteforce"]
    assert bf["tp"] == 0, "alert from different user must not match"
    assert bf["fp"] >= 1, "it should be a false positive"


def test_train_redteam_excluded_from_test_recall():
    # A red-team event in the train period must NOT be in the test recall denominator.
    rows = []
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    res = _run(rows, [f"{BASE + 50},U1@DOM1,C1,C2",   # train red-team (day 1)
                      f"{BASE + 2 * DAY + 100},U1@DOM1,C1,C2"])  # test red-team (day 2)
    bf = res["bruteforce"]
    # Alert at ~BASE+2*DAY+40 matches the test red-team at BASE+2*DAY+100 only if within delay.
    assert bf["recall_denominator_test_rt"] == 1, "only test-period red-team events count"


def test_redteam_event_not_reused():
    # Two alerts must not both consume the same single red-team event.
    # Build two separate brute-force keys, but only one red-team event for key (U1,C1).
    rows = []
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + 1000 + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    # one red-team event at BASE+2*DAY+30 -> only the FIRST alert (at +40) can match.
    res = _run(rows, [f"{BASE + 2 * DAY + 30},U1@DOM1,C1,C2"], failed_threshold=5)
    bf = res["bruteforce"]
    assert bf["tp"] <= 1, "a single red-team event must not be reused for multiple alerts"


def test_pre_attack_alert_is_false_positive():
    # Alert fires BEFORE the ground-truth event time -> must be FP, no TTD.
    rows = []
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    # ground truth occurs AFTER the 5th failure (which is at BASE+2*DAY+40).
    res = _run(rows, [f"{BASE + 2 * DAY + 200},U1@DOM1,C1,C2"])
    bf = res["bruteforce"]
    assert bf["tp"] == 0, "pre-attack alert must be a false positive"
    assert bf["fp"] >= 1


def test_ttd_non_negative():
    # A matched alert must have TTD >= 0.
    rows = []
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    res = _run(rows, [f"{BASE + 2 * DAY + 30},U1@DOM1,C1,C2"])  # rt before 5th failure at +40
    bf = res["bruteforce"]
    assert bf["median_ttd_s"] is None or bf["median_ttd_s"] >= 0, "TTD must be non-negative"


def test_lateral_and_success_after_failures_present():
    rows = []
    # success-after-failure
    for i in range(6):
        rows.append({"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1", "src_computer": "C1",
                     "dst_computer": "C2", "status": "failed"})
    rows.append({"time": BASE + 2 * DAY + 100, "src_user": "U1@DOM1", "src_computer": "C1",
                 "dst_computer": "C2", "status": "success"})
    # lateral: U3 success from C3 then C4 within window
    rows.append({"time": BASE + 2 * DAY + 200, "src_user": "U3@DOM1", "src_computer": "C3",
                 "dst_computer": "C9", "status": "success"})
    rows.append({"time": BASE + 2 * DAY + 300, "src_user": "U3@DOM1", "src_computer": "C4",
                 "dst_computer": "C9", "status": "success"})
    res = _run(rows, [f"{BASE + 2 * DAY + 90},U1@DOM1,C1,C2"], failed_threshold=5)
    assert "success_after_failures" in res
    assert "lateral" in res
    assert res["success_after_failures"]["n_alerts"] >= 1
    assert res["lateral"]["n_alerts"] >= 1


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)