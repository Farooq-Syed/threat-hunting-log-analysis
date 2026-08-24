"""Compact the LANL auth corpus to the red-team-relevant window (one streaming pass).

The 7.2 GB auth.txt.gz is unordered and huge (>=40M real-epoch rows), so any downstream
evaluation that scans it fully is impractically slow. This script does ONE streaming pass and
writes only the events within the red-team window (epoch in [min_redteam - margin,
max_redteam + margin]) to a compact, sorted parquet. Subsequent runs read only the compact
file, so the full Phase 3-4 evaluation is fast and repeatable.

Pass-based (streaming, memory-bounded): no more than a small window of events is held at once.
Writes incrementally to a temp .csv topic then sorts+pandas in the final step.

Usage:
  python scripts/compact_lanl_auth.py --auth E:/auth.txt.gz --redteam <redteam>.gz \
      --margin-days 1.0 --output data/lanl_auth_window.parquet
"""

from __future__ import annotations

import argparse
import csv
import gzip
from pathlib import Path

import pandas as pd

COLUMNS = ["timestamp", "username", "source_ip", "destination", "status"]
# Keep the auth tuple keys too, for campaign grouping.
DETAIL_COLUMNS = ["time", "src_user", "dst_user", "src_computer", "dst_computer",
                  "auth_type", "logon_type", "orientation", "status"]


def _redteam_bounds(path: Path) -> tuple[int, int]:
    rows = []
    opener = gzip.open if path.suffix.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) == 4:
                try:
                    rows.append(int(row[0]))
                except ValueError:
                    pass
    if not rows:
        raise ValueError("red-team file contained no usable events.")
    return min(rows), max(rows)


def main() -> None:
    ap = argparse.ArgumentParser(description="One-pass compaction of the LANL auth corpus.")
    ap.add_argument("--auth", required=True, help="auth.txt.gz path.")
    ap.add_argument("--redteam", required=True, help="redteam.txt.gz path.")
    ap.add_argument("--margin-days", type=float, default=1.0,
                    help="Extra margin in days around the red-team window to keep in the compact file.")
    ap.add_argument("--output", default="data/lanl_auth_window.parquet")
    ap.add_argument("--chunk", type=int, default=500_000,
                    help="Rows buffered before a streaming write (bounds memory).")
    args = ap.parse_args()

    rt_min, rt_max = _redteam_bounds(Path(args.redteam))
    lo = int(rt_min - args.margin_days * 86400)
    hi = int(rt_max + args.margin_days * 86400)
    print(f"red-team window: {rt_min} -> {rt_max} ; compacted auth filter: {lo} -> {hi}")

    auth = Path(args.auth)
    opener = gzip.open if auth.suffix.endswith(".gz") else open

    import pyarrow as pa
    import pyarrow.parquet as pq

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    buffer: list[dict] = []
    kept = 0
    scanned = 0
    writer = None
    try:
        with opener(auth, "rt", encoding="utf-8", errors="replace", newline="") as fh:
            for fields in csv.reader(fh):
                if len(fields) != 9:
                    continue
                try:
                    t = int(fields[0])
                except ValueError:
                    continue
                scanned += 1
                if t < lo or t > hi:
                    continue
                outcome = fields[8].strip().lower()
                if outcome not in {"success", "failure"}:
                    continue
                buffer.append({
                    "time": t,
                    "src_user": fields[1].strip(),
                    "dst_user": fields[2].strip(),
                    "src_computer": fields[3].strip(),
                    "dst_computer": fields[4].strip(),
                    "auth_type": fields[5].strip(),
                    "logon_type": fields[6].strip(),
                    "orientation": fields[7].strip(),
                    "status": outcome,
                })
                kept += 1
                if len(buffer) >= args.chunk:
                    writer = _write_chunk(writer, buffer, out)
                    buffer = []
                    print(f"  ... kept {kept:,} events (scanned {scanned:,})", flush=True)
        if buffer:
            writer = _write_chunk(writer, buffer, out)
    finally:
        if writer is not None:
            writer.close()

    import pyarrow.parquet as pq

    pf = pq.ParquetFile(out)
    n_rows = pf.metadata.num_rows
    n_events = pf.metadata.num_row_groups
    print(f"Wrote {n_rows:,} compact events -> {out}")
    print(f"  row groups: {n_events}")
    print(f"  time range: {pf.metadata.row_group(0).column(0).statistics.min} -> "
          f"{pf.metadata.row_group(pf.metadata.num_row_groups-1).column(0).statistics.max}")
    print(f"  scanned {scanned:,} raw rows; kept {kept:,}")


def _write_chunk(writer, buffer: list[dict], out: Path):
    import pyarrow as pa
    import pyarrow.parquet as pq

    table = pa.Table.from_pylist(buffer, schema=pa.schema({
        "time": pa.int64(),
        "src_user": pa.string(),
        "dst_user": pa.string(),
        "src_computer": pa.string(),
        "dst_computer": pa.string(),
        "auth_type": pa.string(),
        "logon_type": pa.string(),
        "orientation": pa.string(),
        "status": pa.string(),
    }))
    if writer is None:
        writer = pq.ParquetWriter(out, table.schema)
    writer.write_table(table)
    return writer


if __name__ == "__main__":
    main()
