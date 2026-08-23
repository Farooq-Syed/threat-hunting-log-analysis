"""Unit tests for the newer detection paths in log_hunter.

These cover the additions that build on the original three detectors: time-window
burst detection, success-from-a-new-source lateral movement, and the pure XML
conversion used for .evtx parsing. Like the rest of the suite, each test feeds a
small hand-built frame so the behavior is checked in isolation.
"""

import sys
import unittest
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import log_hunter  # noqa: E402


def make_frame(rows):
    frame = pd.DataFrame(rows)
    frame["status"] = frame["status"].astype(str).str.strip().str.lower()
    frame["event_time"] = log_hunter.parse_timestamps(frame["timestamp"])
    return frame


class BurstActivityTests(unittest.TestCase):
    def test_dense_run_within_window_is_flagged(self):
        rows = [
            {"timestamp": f"2026-05-10T08:0{i}:00", "username": "u",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(5)
        ]
        result = log_hunter.detect_burst_activity(make_frame(rows), window_minutes=5, min_failures=5)
        self.assertEqual(len(result), 1)
        self.assertEqual(int(result.iloc[0]["peak_failures"]), 5)

    def test_slow_drip_is_not_a_burst(self):
        # Five failures spaced hours apart: total count is high but no window is dense.
        rows = [
            {"timestamp": f"2026-05-10T0{i}:00:00", "username": "u",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(5)
        ]
        result = log_hunter.detect_burst_activity(make_frame(rows), window_minutes=5, min_failures=5)
        self.assertTrue(result.empty)

    def test_no_failures_returns_empty_not_crash(self):
        rows = [{"timestamp": "2026-05-10T08:00:00", "username": "amy",
                 "source_ip": "10.0.0.1", "event_type": "login", "status": "success"}]
        result = log_hunter.detect_burst_activity(make_frame(rows), window_minutes=5, min_failures=5)
        self.assertTrue(result.empty)


class LateralMovementTests(unittest.TestCase):
    def test_success_from_new_source_within_window_flagged(self):
        rows = [
            {"timestamp": "2026-05-10T08:00:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "success"},
            {"timestamp": "2026-05-10T09:00:00", "username": "bob",
             "source_ip": "172.16.0.5", "event_type": "login", "status": "success"},
        ]
        result = log_hunter.detect_lateral_movement(make_frame(rows), window_hours=24)
        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]["username"], "bob")
        self.assertIn("10.0.0.9", result.iloc[0]["details"])

    def test_change_beyond_window_not_flagged(self):
        rows = [
            {"timestamp": "2026-05-08T08:00:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "success"},
            {"timestamp": "2026-05-10T09:00:00", "username": "bob",
             "source_ip": "172.16.0.5", "event_type": "login", "status": "success"},
        ]
        result = log_hunter.detect_lateral_movement(make_frame(rows), window_hours=24)
        self.assertTrue(result.empty)

    def test_same_source_not_flagged(self):
        rows = [
            {"timestamp": "2026-05-10T08:00:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "success"},
            {"timestamp": "2026-05-10T09:00:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "success"},
        ]
        result = log_hunter.detect_lateral_movement(make_frame(rows), window_hours=24)
        self.assertTrue(result.empty)


class EvtxRecordParsingTests(unittest.TestCase):
    def test_4625_failure_record(self):
        xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4625</EventID>"
            '<TimeCreated SystemTime="2026-05-10T08:03:11.000Z"/></System>'
            "<EventData>"
            '<Data Name="TargetUserName">admin</Data>'
            '<Data Name="IpAddress">203.0.113.7</Data>'
            "</EventData></Event>"
        )
        record = log_hunter.parse_evtx_record_xml(xml_text)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["username"], "admin")
        self.assertEqual(record["source_ip"], "203.0.113.7")

    def test_4624_success_record(self):
        xml_text = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>4624</EventID></System>"
            "<EventData>"
            '<Data Name="TargetUserName">svc-deploy</Data>'
            '<Data Name="IpAddress">10.0.0.9</Data>'
            "</EventData></Event>"
        )
        record = log_hunter.parse_evtx_record_xml(xml_text)
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["username"], "svc-deploy")

    def test_unrelated_event_id_is_skipped(self):
        xml_text = (
            '<Event><System><EventID>4688</EventID></System>'
            '<EventData><Data Name="TargetUserName">admin</Data></EventData></Event>'
        )
        record = log_hunter.parse_evtx_record_xml(xml_text)
        self.assertEqual(record["status"], "skipped")


class DetectorAgreementTests(unittest.TestCase):
    def _frame(self):
        base = pd.Timestamp("2026-01-01 00:00:00")
        rows = []
        # IP A: 6 failures within ~2 minutes, then a success -> bruteforce + burst +
        # success_after_failures all fire on it.
        for i, minute in enumerate([0, 1, 1, 2, 2, 3]):
            rows.append({"timestamp": base, "username": "bob", "source_ip": "10.0.0.9",
                         "status": "failed", "event_time": base + pd.Timedelta(minutes=minute)})
        rows.append({"timestamp": base, "username": "bob", "source_ip": "10.0.0.9",
                     "status": "success", "event_time": base + pd.Timedelta(minutes=4)})
        # IP B: 6 failures spread over 6 hours -> bruteforce fires, burst does not
        # (outside the window), and there is no success. This is the detector that a
        # rules-only view would flag but the burst view would miss -> disagreement.
        for hour in range(6):
            rows.append({"timestamp": base, "username": "carol", "source_ip": "10.0.0.42",
                         "status": "failed", "event_time": base + pd.Timedelta(hours=hour)})
        return pd.DataFrame(rows)

    def test_agreement_measures_partial_overlap(self):
        agreement = log_hunter.detector_agreement(self._frame(), failed_threshold=5,
                                                 window_minutes=5, lateral_window_hours=24)
        self.assertEqual(agreement["per_detector_flagged_ips"]["bruteforce"], 2)
        self.assertEqual(agreement["per_detector_flagged_ips"]["burst"], 1)
        self.assertEqual(agreement["per_detector_flagged_ips"]["success_after_failures"], 1)
        self.assertEqual(agreement["total_distinct_ips_flagged"], 2)
        # One IP is flagged by a single detector only (the slow-drip brute force).
        self.assertEqual(agreement["ips_flagged_by_1_detector_only"], 1)
        # bruteforce and burst overlap on the one genuine burst IP.
        pair = {tuple(sorted((p["detector_a"], p["detector_b"]))): p for p in agreement["pairwise"]}
        self.assertAlmostEqual(pair[("bruteforce", "burst")]["jaccard"], 0.5)
        self.assertEqual(agreement["ips_flagged_by_2_or_more"], 1)


if __name__ == "__main__":
    unittest.main()
