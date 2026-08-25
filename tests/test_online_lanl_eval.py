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

from scripts.online_lanl_eval import (  # noqa: E402
    _build_sorted_parquet, _prepare_chronological_parquet, _stream_and_eval, _redteam)

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
        sorted_frame = d / "sorted.parquet"
        _build_sorted_parquet(f, sorted_frame)
        rt = _redteam(rt_path)
        res = _stream_and_eval(
            sorted_frame, rt, split_day, kw.get("delay_s", 1800),
            kw.get("failed_threshold", 5), kw.get("window_s", 60),
            kw.get("lateral_s", 86400))
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


def test_alert_burden_and_fpr_proxy_have_distinct_denominators():
    rows = [
        {"time": BASE + 2 * DAY + i * 10, "src_user": "U2@DOM1",
         "src_computer": "C1", "dst_computer": "C2", "status": "failed"}
        for i in range(6)
    ]
    res = _run(rows, [f"{BASE + 2 * DAY + 100},U1@DOM1,C9,C2"])
    bf = res["bruteforce"]
    assert bf["test_day_count"] == 1
    assert bf["alerts_per_analyst_day"] == bf["n_alerts"]
    assert bf["false_alert_key_days"] == 1
    assert bf["negative_key_day_denominator"] == 1
    assert bf["fpr_proxy_negative_key_days"] == 1.0


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


def test_sorted_parquet_is_chronological_and_normalizes_status():
    rows = [
        {"time": BASE + 30, "src_user": "U2", "src_computer": "C2",
         "dst_computer": "C9", "status": " FAILURE "},
        {"time": BASE + 10, "src_user": "U1", "src_computer": "C1",
         "dst_computer": "C9", "status": "Success"},
        {"time": BASE + 20, "src_user": "U1", "src_computer": "C1",
         "dst_computer": "C9", "status": "FAIL"},
    ]
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        source = _write_frame(rows, d / "source.parquet")
        output = d / "sorted.parquet"
        _build_sorted_parquet(source, output)
        frame = pq.read_table(output).to_pandas()
        assert frame["time"].tolist() == sorted(frame["time"].tolist())
        assert frame["status"].tolist() == ["success", "failed", "failed"]
        assert output.with_suffix(".parquet.done").exists()


def test_chronological_source_is_reused_without_copy():
    rows = [
        {"time": BASE + i, "src_user": "U1", "src_computer": "C1",
         "dst_computer": "C2", "status": "success"}
        for i in range(3)
    ]
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        source = _write_frame(rows, d / "source.parquet")
        unused_output = d / "sorted.parquet"
        chosen = _prepare_chronological_parquet(source, unused_output)
        assert chosen == source
        assert not unused_output.exists()


def test_detectors_match_ground_truth_independently():
    # The fifth failure triggers brute-force and burst at the same timestamp. Each detector's
    # recall must be evaluated independently against the same red-team event.
    event_time = BASE + 2 * DAY + 30
    rows = [
        {"time": BASE + 2 * DAY + i * 10, "src_user": "U1@DOM1",
         "src_computer": "C1", "dst_computer": "C2", "status": "failed"}
        for i in range(6)
    ]
    res = _run(rows, [f"{event_time},U1@DOM1,C1,C2"], failed_threshold=5, window_s=60)
    assert res["bruteforce"]["tp"] == 1
    assert res["burst"]["tp"] == 1


def test_repeated_successes_preserve_lateral_semantics():
    # Repeated events from one source must collapse to its latest timestamp; a later success
    # from another source inside the horizon still triggers lateral movement.
    start = BASE + 2 * DAY
    rows = [
        {"time": start + i, "src_user": "U1@DOM1", "src_computer": "C1",
         "dst_computer": "C9", "status": "success"}
        for i in range(1000)
    ]
    rows.append({"time": start + 1001, "src_user": "U1@DOM1", "src_computer": "C2",
                 "dst_computer": "C9", "status": "success"})
    res = _run(rows, [f"{start + 1000},U1@DOM1,C2,C9"], lateral_s=3600)
    assert res["lateral"]["n_alerts"] >= 1


if __name__ == "__main__":
    import unittest

    unittest.main(verbosity=2)
