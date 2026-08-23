"""Evaluate THLA against the labeled synthetic auth-log generator output.

This is not a substitute for real-world benchmarking, but it does turn the
synthetic log generator into something measurable: we can check whether the tool
recovers the brute-force campaigns and the compromised-success cases that the
generator explicitly injected.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

import log_hunter


DEFAULT_INPUT = "data/synthetic_auth_logs.csv"
DEFAULT_OUTPUT = "output/synthetic_eval_metrics.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate THLA on labeled synthetic auth logs.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to labeled synthetic auth logs.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Path to metrics JSON.")
    parser.add_argument("--failed-threshold", type=int, default=5)
    parser.add_argument("--window-minutes", type=int, default=5)
    parser.add_argument("--lateral-window-hours", type=int, default=24)
    return parser


def _pair_set(frame: pd.DataFrame) -> set[tuple[str, str]]:
    if frame.empty:
        return set()
    return {
        (str(row["source_ip"]), str(row["username"]))
        for _, row in frame.iterrows()
    }


def main() -> None:
    args = build_parser().parse_args()
    input_path = Path(args.input)
    dataframe = log_hunter.load_logs(input_path, "csv")
    raw = pd.read_csv(input_path)

    brute_force_expected = raw[raw["scenario_type"].isin(["brute_force_attempt", "successful_login_after_failures"])]
    brute_force_expected = brute_force_expected[brute_force_expected["status"] == "failed"]
    brute_force_expected = (
        brute_force_expected.groupby(["source_ip", "username"])
        .size()
        .reset_index(name="failed_attempts")
    )
    brute_force_expected = brute_force_expected[brute_force_expected["failed_attempts"] >= args.failed_threshold]

    success_expected = raw[raw["scenario_type"] == "successful_login_after_failures"]
    success_expected = success_expected[success_expected["status"] == "success"][["source_ip", "username"]].drop_duplicates()

    brute_force_found = log_hunter.detect_bruteforce(dataframe, args.failed_threshold)
    success_found = log_hunter.detect_success_after_failures(dataframe, args.failed_threshold)
    report = log_hunter.build_report(
        dataframe,
        args.failed_threshold,
        args.window_minutes,
        args.lateral_window_hours,
    )

    expected_brute_force_pairs = _pair_set(brute_force_expected)
    found_brute_force_pairs = _pair_set(brute_force_found)
    expected_success_pairs = _pair_set(success_expected)
    found_success_pairs = _pair_set(success_found)

    brute_force_hits = expected_brute_force_pairs & found_brute_force_pairs
    success_hits = expected_success_pairs & found_success_pairs

    payload = {
        "rows": int(len(raw)),
        "findings_count": int(len(report)),
        "expected_brute_force_pairs": int(len(expected_brute_force_pairs)),
        "detected_brute_force_pairs": int(len(brute_force_hits)),
        "brute_force_recall": round(len(brute_force_hits) / max(1, len(expected_brute_force_pairs)), 4),
        "expected_success_after_failures_pairs": int(len(expected_success_pairs)),
        "detected_success_after_failures_pairs": int(len(success_hits)),
        "success_after_failures_recall": round(len(success_hits) / max(1, len(expected_success_pairs)), 4),
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Rows processed                     : {payload['rows']}")
    print(f"Findings generated                 : {payload['findings_count']}")
    print(
        "Brute-force recall                : "
        f"{payload['detected_brute_force_pairs']}/{payload['expected_brute_force_pairs']} "
        f"({payload['brute_force_recall']:.3f})"
    )
    print(
        "Success-after-failures recall     : "
        f"{payload['detected_success_after_failures_pairs']}/"
        f"{payload['expected_success_after_failures_pairs']} "
        f"({payload['success_after_failures_recall']:.3f})"
    )
    print(f"Metrics written to                : {output_path}")


if __name__ == "__main__":
    main()
