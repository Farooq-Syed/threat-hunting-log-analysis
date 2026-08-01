"""Generate a larger synthetic authentication-log dataset.

The bundled samples are small and hand-built, which is fine for a smoke test but too
small for the findings to carry weight. This script produces a larger normalized-CSV
auth log (the format detector "csv") mixing normal user activity with several attack
patterns, so the detectors can be exercised at scale.

The data is SYNTHETIC — user names, IPs, and timing are generated, not captured. It is
for development and demonstration, not a benchmark. For real evaluation, point the tool
at genuine `auth.log` files or Windows Security event exports (see the README).

Attack patterns modeled:
  - brute force: one source IP hammering one account with many failures, sometimes
    followed by a success (a simulated credential compromise);
  - password spraying: one source IP trying many accounts with a few failures each;
  - normal activity: users logging in successfully, with the occasional fat-finger
    failed attempt.

Usage:
    python generate_auth_logs.py --rows 3000 --output data/synthetic_auth_logs.csv
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mallory", "oscar", "peggy", "trent", "victor"]
INTERNAL_IPS = [f"192.168.1.{n}" for n in range(10, 40)]
EXTERNAL_IPS = ["203.0.113.5", "198.51.100.44", "203.0.113.77", "45.83.12.9",
                "185.220.101.4", "91.219.236.20"]


def _normal_activity(rng, start, rows):
    records = []
    t = start
    for _ in range(rows):
        t += timedelta(seconds=int(rng.integers(20, 600)))
        user = rng.choice(USERS)
        ip = rng.choice(INTERNAL_IPS)
        # mostly successes, occasional genuine failed attempt
        status = "failed" if rng.random() < 0.12 else "success"
        records.append((t, user, ip, "login", status))
    return records


def _brute_force(rng, start):
    """A run of failures against one account from one IP, maybe then a success."""
    records = []
    t = start
    user = rng.choice(USERS)
    ip = rng.choice(EXTERNAL_IPS)
    n_fail = int(rng.integers(6, 25))
    for _ in range(n_fail):
        t += timedelta(seconds=int(rng.integers(1, 8)))
        records.append((t, user, ip, "login", "failed"))
    if rng.random() < 0.4:  # sometimes the attacker eventually gets in
        t += timedelta(seconds=int(rng.integers(1, 8)))
        records.append((t, user, ip, "login", "success"))
    return records


def _password_spray(rng, start):
    """One IP trying many accounts with a few failures each."""
    records = []
    t = start
    ip = rng.choice(EXTERNAL_IPS)
    targets = rng.choice(USERS, size=int(rng.integers(6, 12)), replace=False)
    for user in targets:
        for _ in range(int(rng.integers(1, 4))):
            t += timedelta(seconds=int(rng.integers(2, 20)))
            records.append((t, user, ip, "login", "failed"))
    return records


def generate(rows: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    start = datetime(2026, 5, 10, 8, 0, 0)
    records = []

    # Interleave bursts of attacks among normal activity until we reach ~rows.
    while len(records) < rows:
        records += _normal_activity(rng, start + timedelta(seconds=len(records) * 30),
                                    rows=int(rng.integers(20, 60)))
        roll = rng.random()
        anchor = start + timedelta(seconds=len(records) * 30)
        if roll < 0.5:
            records += _brute_force(rng, anchor)
        elif roll < 0.75:
            records += _password_spray(rng, anchor)

    records = records[:rows]
    records.sort(key=lambda r: r[0])
    frame = pd.DataFrame(records, columns=["timestamp", "username", "source_ip",
                                           "event_type", "status"])
    frame["timestamp"] = frame["timestamp"].map(lambda d: d.isoformat())
    return frame


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate synthetic auth logs (CSV).")
    parser.add_argument("--rows", type=int, default=3000)
    parser.add_argument("--output", default="data/synthetic_auth_logs.csv")
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    frame = generate(args.rows, args.seed)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out, index=False)
    fails = int((frame["status"] == "failed").sum())
    print(f"Wrote {len(frame)} events to {out}")
    print(f"Failed events: {fails} ({100 * fails / len(frame):.1f}%), "
          f"unique source IPs: {frame['source_ip'].nunique()}")


if __name__ == "__main__":
    main()
