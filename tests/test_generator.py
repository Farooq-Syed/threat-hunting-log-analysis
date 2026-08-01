"""Tests for generate_auth_logs.py.

Checks schema, size, reproducibility, and that the generated log actually contains
both attack signal (runs of failures from external IPs) and normal successes, so the
detectors have something to find.
"""

import sys
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import generate_auth_logs as gen  # noqa: E402


class AuthLogGeneratorTests(unittest.TestCase):
    def test_schema_and_size(self):
        frame = gen.generate(rows=500, seed=1)
        self.assertEqual(len(frame), 500)
        self.assertEqual(
            list(frame.columns),
            ["timestamp", "username", "source_ip", "event_type", "status"],
        )

    def test_contains_both_statuses(self):
        frame = gen.generate(rows=500, seed=1)
        self.assertEqual(set(frame["status"]), {"failed", "success"})

    def test_reproducible_with_seed(self):
        a = gen.generate(rows=300, seed=5)
        b = gen.generate(rows=300, seed=5)
        self.assertTrue(a.equals(b))

    def test_has_a_bruteforce_signal(self):
        # At least one (source_ip, username) pair should exceed the default
        # brute-force threshold of 5 failures, or the data would be uninteresting.
        frame = gen.generate(rows=1000, seed=3)
        failures = frame[frame["status"] == "failed"]
        counts = failures.groupby(["source_ip", "username"]).size()
        self.assertTrue((counts >= 5).any())

    def test_timestamps_are_sorted_iso(self):
        frame = gen.generate(rows=300, seed=2)
        stamps = frame["timestamp"].tolist()
        self.assertEqual(stamps, sorted(stamps))


if __name__ == "__main__":
    unittest.main()
