"""Streaming evaluation on LANL authentication and red-team ground truth.

The full authentication file is several gigabytes compressed, so this evaluator
never loads it into pandas. It measures exact ground-truth event coverage and a
targeted lateral-movement candidate recall for users present in the red-team file.
The candidate precision is explicitly limited to those users and is not a global
false-positive estimate.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
from typing import TextIO


def open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return path.open("r", encoding="utf-8", errors="replace", newline="")


def load_redteam(path: Path) -> set[tuple[int, str, str, str]]:
    events: set[tuple[int, str, str, str]] = set()
    with open_text(path) as handle:
        for row in csv.reader(handle):
            if len(row) != 4:
                continue
            try:
                events.add((int(row[0]), row[1].strip(), row[2].strip(), row[3].strip()))
            except ValueError:
                continue
    if not events:
        raise ValueError("The LANL red-team file contained no usable events.")
    return events


def evaluate(auth_path: Path, redteam_path: Path, window_hours: int = 24) -> dict:
    ground_truth = load_redteam(redteam_path)
    ground_truth_pairs = {(user, source) for _, user, source, _ in ground_truth}
    target_users = {user for _, user, _, _ in ground_truth}
    last_success: dict[str, tuple[int, str]] = {}
    candidates: set[tuple[str, str]] = set()
    matched_events: set[tuple[int, str, str, str]] = set()
    auth_rows = 0
    malformed_rows = 0
    digest = hashlib.sha256()
    cutoff = window_hours * 3600

    with auth_path.open("rb") as raw_handle:
        stream = gzip.GzipFile(fileobj=raw_handle) if auth_path.suffix.lower() == ".gz" else raw_handle
        for raw_line in stream:
            digest.update(raw_line)
            try:
                row = next(csv.reader([raw_line.decode("utf-8", errors="replace")]))
            except (csv.Error, UnicodeError):
                malformed_rows += 1
                continue
            if len(row) != 9:
                malformed_rows += 1
                continue
            try:
                timestamp = int(row[0])
            except ValueError:
                malformed_rows += 1
                continue
            auth_rows += 1
            user = row[1].strip()
            source = row[3].strip()
            destination = row[4].strip()
            outcome = row[8].strip().lower()
            event = (timestamp, user, source, destination)
            if event in ground_truth:
                matched_events.add(event)
            if outcome != "success" or user not in target_users:
                continue
            prior = last_success.get(user)
            if prior and source != prior[1] and 0 <= timestamp - prior[0] <= cutoff:
                candidates.add((user, source))
            last_success[user] = (timestamp, source)

    detected = candidates & ground_truth_pairs
    return {
        "scope": "LANL red-team users only; candidate precision is not a global false-positive rate",
        "window_hours": window_hours,
        "auth_rows": auth_rows,
        "malformed_auth_rows": malformed_rows,
        "ground_truth_events": len(ground_truth),
        "ground_truth_pairs": len(ground_truth_pairs),
        "exact_ground_truth_events_present": len(matched_events),
        "targeted_lateral_candidates": len(candidates),
        "detected_ground_truth_pairs": len(detected),
        "ground_truth_pair_recall": len(detected) / len(ground_truth_pairs),
        "targeted_candidate_precision": len(detected) / len(candidates) if candidates else 0.0,
        "provenance": {
            "auth_path": str(auth_path),
            "auth_content_sha256": digest.hexdigest(),
            "redteam_path": str(redteam_path),
            "redteam_file_sha256": hashlib.sha256(redteam_path.read_bytes()).hexdigest(),
            "source_url": "https://csr.lanl.gov/data/cyber1/",
            "citation_doi": "10.17021/1179829",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate lateral-movement candidates on LANL auth/red-team data.")
    parser.add_argument("--auth", required=True, help="LANL auth.txt or auth.txt.gz")
    parser.add_argument("--redteam", required=True, help="LANL redteam.txt or redteam.txt.gz")
    parser.add_argument("--window-hours", type=int, default=24)
    parser.add_argument("--output", default="results/lanl_external_validation.json")
    args = parser.parse_args()

    payload = evaluate(Path(args.auth), Path(args.redteam), args.window_hours)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
