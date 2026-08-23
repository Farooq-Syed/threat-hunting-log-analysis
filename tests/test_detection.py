"""Unit tests for the detection logic in log_hunter.

These import the functions directly and feed them small hand-built DataFrames so
each detector can be checked in isolation, independent of the sample files.
"""

import sys
import unittest
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import log_hunter  # noqa: E402


def make_frame(rows):
    """Build a normalised events frame the way load_logs would hand it on.

    Mirrors load_logs: status lower-cased and an event_time column parsed from
    the timestamp, so the detectors see exactly what they see in production.
    """
    frame = pd.DataFrame(rows)
    frame["status"] = frame["status"].astype(str).str.strip().str.lower()
    frame["event_time"] = log_hunter.parse_timestamps(frame["timestamp"])
    return frame


class BruteForceTests(unittest.TestCase):
    def test_flags_ip_user_over_threshold(self):
        rows = [
            {"timestamp": f"2026-05-10T08:0{i}:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(5)
        ]
        frame = make_frame(rows)
        result = log_hunter.detect_bruteforce(frame, threshold=5)
        self.assertEqual(len(result), 1)
        self.assertEqual(int(result.iloc[0]["failed_attempts"]), 5)

    def test_below_threshold_not_flagged(self):
        rows = [
            {"timestamp": f"2026-05-10T08:0{i}:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(3)
        ]
        result = log_hunter.detect_bruteforce(make_frame(rows), threshold=5)
        self.assertTrue(result.empty)

    def test_no_failures_returns_empty_not_crash(self):
        rows = [{"timestamp": "2026-05-10T08:00:00", "username": "amy",
                 "source_ip": "10.0.0.1", "event_type": "login", "status": "success"}]
        result = log_hunter.detect_bruteforce(make_frame(rows), threshold=5)
        self.assertTrue(result.empty)


class SuccessAfterFailuresTests(unittest.TestCase):
    def test_detects_success_after_enough_failures(self):
        rows = [
            {"timestamp": f"2026-05-10T08:0{i}:00", "username": "bob",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(5)
        ]
        rows.append({"timestamp": "2026-05-10T08:06:00", "username": "bob",
                     "source_ip": "10.0.0.9", "event_type": "login", "status": "success"})
        result = log_hunter.detect_success_after_failures(make_frame(rows), threshold=5)
        self.assertEqual(len(result), 1)

    def test_chronology_uses_parsed_time_not_string_order(self):
        # Rows deliberately given out of chronological order with month-name
        # timestamps. A lexical string sort would order these Dec, Feb, Jan and
        # miscount the run of failures; a datetime sort orders them correctly.
        rows = [
            {"timestamp": "Feb 01 08:00:00", "username": "eve",
             "source_ip": "10.0.0.7", "event_type": "login", "status": "failed"},
            {"timestamp": "Jan 01 08:00:00", "username": "eve",
             "source_ip": "10.0.0.7", "event_type": "login", "status": "failed"},
            {"timestamp": "Mar 01 08:00:00", "username": "eve",
             "source_ip": "10.0.0.7", "event_type": "login", "status": "success"},
        ]
        # Only 2 failures precede the success chronologically, so threshold 3 must
        # NOT flag this. With a buggy string sort the ordering could differ.
        result = log_hunter.detect_success_after_failures(make_frame(rows), threshold=3)
        self.assertTrue(result.empty)


class UnusualIpActivityTests(unittest.TestCase):
    def test_single_ip_not_flagged(self):
        rows = [
            {"timestamp": f"2026-05-10T08:0{i}:00", "username": f"u{i}",
             "source_ip": "10.0.0.9", "event_type": "login", "status": "failed"}
            for i in range(6)
        ]
        result = log_hunter.detect_unusual_ip_activity(make_frame(rows))
        self.assertTrue(result.empty)

    def test_outlier_ip_flagged(self):
        rows = []
        # Three quiet IPs with one event each.
        for i in range(3):
            rows.append({"timestamp": "2026-05-10T08:00:00", "username": "u",
                         "source_ip": f"10.0.0.{i}", "event_type": "login", "status": "success"})
        # One very loud IP hitting many distinct users.
        for i in range(20):
            rows.append({"timestamp": "2026-05-10T09:00:00", "username": f"user{i}",
                         "source_ip": "10.0.0.99", "event_type": "login", "status": "failed"})
        result = log_hunter.detect_unusual_ip_activity(make_frame(rows))
        self.assertIn("10.0.0.99", set(result["source_ip"]))


class WindowsParsingTests(unittest.TestCase):
    def test_coerce_event_id_handles_blank(self):
        self.assertEqual(log_hunter._coerce_event_id(""), -1)
        self.assertEqual(log_hunter._coerce_event_id(None), -1)
        self.assertEqual(log_hunter._coerce_event_id("4625"), 4625)
        self.assertEqual(log_hunter._coerce_event_id(4624.0), 4624)

    def test_first_present_skips_null(self):
        row = pd.Series({"TargetUserName": None, "AccountName": "svc-admin"})
        self.assertEqual(
            log_hunter._first_present(row, ["TargetUserName", "AccountName"], "unknown"),
            "svc-admin",
        )


class LanlParsingTests(unittest.TestCase):
    def test_parses_official_auth_schema_and_skips_malformed_rows(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            path = Path(directory) / "auth.txt"
            path.write_text(
                "1,C625$@DOM1,U147@DOM1,C625,C625,Negotiate,Batch,LogOn,Success\n"
                "2,U10@DOM1,U20@DOM1,C10,C20,Kerberos,Network,LogOn,Failure\n"
                "malformed,row\n",
                encoding="utf-8",
            )
            frame = log_hunter.parse_lanl_auth(path)

        self.assertEqual(len(frame), 2)
        self.assertEqual(frame.iloc[0]["source_ip"], "C625")
        self.assertEqual(frame.iloc[0]["status"], "success")
        self.assertEqual(frame.iloc[1]["status"], "failed")
        self.assertEqual(frame.iloc[1]["destination"], "C20")


if __name__ == "__main__":
    unittest.main()
