"""Compact the LANL auth corpus to the red-team-relevant window (one streaming pass).

Two-stage design for throughput:

Stage 1 (streaming filter, raw I/O): read the 68 GB uncompressed (or the 7.2 GB gzip)
auth file once, keep events in the red-team window that (a) touch a red-team user or a
red-team source/destination computer (complete recall signal) or (b) pass a deterministic
benign-background sample (for the false-positive / alert-burden frame). Kept lines are
written verbatim to a compact text file. This is pure disk I/O - no per-row dict, no
pyarrow - so it runs at the read throughput of the source.

Stage 2 (encode): read the compact text file and write a single parquet. Because Stage 1
dropped most of the corpus, this pass is small and fast.

Verification gate (written to <output>.manifest.json and gated by <output>.done):
  * SHA-256 of inputs and output,
  * scanned / kept row counts,
  * red-team window overlap with the retained auth window,
  * a completion marker only after the parquet writer is closed (interrupted runs are
    detectable as an absent marker).

Usage:
  python scripts/compact_lanl_auth.py --auth E:/auth.txt --redteam <redteam>.gz \
      --margin-days 1.0 --benign-sample 0.02 --output data/lanl_auth_window.parquet
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import random
import time
from pathlib import Path

import pandas as pd


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _redteam(path: Path) -> tuple[int, int, set[str], set[str]]:
    """Return (min, max, users, computers) from the red-team file."""
    import csv

    times: list[int] = []
    users: set[str] = set()
    computers: set[str] = set()
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) != 4:
                continue
            try:
                times.append(int(row[0]))
            except ValueError:
                continue
            user = row[1].strip()
            if user:
                users.add(user)
            computers.add(row[2].strip())
            computers.add(row[3].strip())
    if not times:
        raise ValueError("red-team file contained no usable events.")
    return min(times), max(times), users, computers


def main() -> None:
    ap = argparse.ArgumentParser(description="Two-stage compaction of the LANL auth corpus.")
    ap.add_argument("--auth", required=True)
    ap.add_argument("--redteam", required=True)
    ap.add_argument("--margin-days", type=float, default=1.0)
    ap.add_argument("--benign-sample", type=float, default=0.02)
    ap.add_argument("--output", default="data/lanl_auth_window.parquet")
    ap.add_argument("--stage2-only", action="store_true",
                    help="Skip the full auth scan; encode the existing <output>.stage1.txt into "
                         "parquet (for when stage1 already ran to completion).")
    args = ap.parse_args()

    rt_min, rt_max, rt_users, rt_computers = _redteam(Path(args.redteam))
    lo = int(rt_min - args.margin_days * 86400)
    hi = int(rt_max + args.margin_days * 86400)
    start = time.time()
    print(f"red-team window: {rt_min} -> {rt_max} ; filter {lo} -> {hi} ; "
          f"users={len(rt_users)} computers={len(rt_computers)} ; benign sample={args.benign_sample}")

    auth = Path(args.auth)
    red = Path(args.redteam)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    done_marker = Path(str(out) + ".done")
    manifest = Path(str(out) + ".manifest.json")
    tmp = Path(str(out) + ".stage1.txt")

    # ---- Stage 1: streaming filter -> raw text (skip if --stage2-only and tmp exists) ----
    if args.stage2_only and tmp.exists() and tmp.stat().st_size > 0:
        scanned = kept = kept_benign = 0
        t_min = t_max = None
        print(f"stage1 skipped (existing {tmp.name}, {tmp.stat().st_size/1e9:.1f} GB)")
        import csv as _csv
        with tmp.open("r", encoding="utf-8", newline="") as fh:
            for row in _csv.reader(fh):
                if len(row) < 9:
                    continue
                kept += 1
                try:
                    t = int(row[0])
                except ValueError:
                    continue
                t_min = t if t_min is None else min(t_min, t)
                t_max = t if t_max is None else max(t_max, t)
        elapsed1 = time.time() - start
    else:
        opener = gzip.open if str(auth).endswith(".gz") else open
        scanned = 0
        kept = 0
        kept_benign = 0
        t_min = None
        t_max = None
        rnd = random.Random(42)
        with opener(auth, "rt", encoding="utf-8", errors="replace", newline="") as fh, \
             tmp.open("w", encoding="utf-8", newline="") as out_fh:
            for line in fh:
                c = line.find(",")
                if c == -1:
                    continue
                try:
                    t = int(line[:c])
                except ValueError:
                    continue
                scanned += 1
                if t < lo or t > hi:
                    continue
                fields = line.split(",")
                if len(fields) != 9:
                    continue
                outcome = fields[8].strip().lower()
                if outcome not in {"success", "fail", "failed", "failure"}:
                    continue
                is_fail = outcome in {"fail", "failed", "failure"}
                src_user = fields[1].strip()
                src_comp = fields[3].strip()
                dst_comp = fields[4].strip()
                is_rt = src_user in rt_users or src_comp in rt_computers or dst_comp in rt_computers
                if not is_rt and rnd.random() >= args.benign_sample:
                    continue
                if not is_rt:
                    kept_benign += 1
                out_fh.write(line)
                kept += 1
                t_min = t if t_min is None else min(t_min, t)
                t_max = t if t_max is None else max(t_max, t)
                if kept % 20_000_000 == 0:
                    print(f"  stage1 ... kept {kept:,} (scanned {scanned:,})", flush=True)
        elapsed1 = time.time() - start
        print(f"stage1 done: scanned {scanned:,} kept {kept:,} in {elapsed1:.0f}s")

    # ---- Stage 2: encode compact text -> parquet, in bounded chunks ----
    import pyarrow as pa
    import pyarrow.parquet as pq

    cols = ["time", "src_user", "dst_user", "src_computer", "dst_computer",
            "auth_type", "logon_type", "orientation", "status"]
    writer = None
    chunk_kept = 0
    for chunk in pd.read_csv(tmp, header=None, names=cols, dtype=str, chunksize=2_000_000):
        chunk["time"] = chunk["time"].astype("int64")
        chunk["status"] = chunk["status"].str.lower()
        chunk["is_redteam_touching"] = (
            chunk["src_user"].isin(rt_users)
            | chunk["src_computer"].isin(rt_computers)
            | chunk["dst_computer"].isin(rt_computers)
        )
        table = pa.Table.from_pandas(chunk, preserve_index=False)
        if writer is None:
            writer = pq.ParquetWriter(out, table.schema)
        writer.write_table(table)
        chunk_kept += len(chunk)
        print(f"  stage2 ... encoded {chunk_kept:,} rows", flush=True)
    if writer is not None:
        writer.close()
    tmp.unlink(missing_ok=True)
    elapsed2 = time.time() - start
    print(f"stage2 done: {chunk_kept:,} rows in {elapsed2 - elapsed1:.0f}s")

    # ---- verification gate ----
    pf = pq.ParquetFile(out)
    parquet_rows = pf.metadata.num_rows
    overlap_ok = bool(parquet_rows > 0 and t_min is not None and t_min <= rt_min and t_max >= rt_max)
    # Count red-team-touching vs benign directly from the parquet (memory-bounded column read).
    rt_touch = 0
    for batch in pf.iter_batches(columns=["is_redteam_touching"], batch_size=2_000_000):
        rt_touch += int(batch.column(0).to_pandas().sum())
    benign_kept = parquet_rows - rt_touch
    info = {
        "input_auth": str(auth), "input_redteam": str(red),
        "auth_sha256": _sha256(auth), "redteam_sha256": _sha256(red),
        "redteam_min": rt_min, "redteam_max": rt_max,
        "auth_filter_min": lo, "auth_filter_max": hi,
        "auth_kept_min": t_min, "auth_kept_max": t_max,
        "scanned": scanned, "kept": kept, "kept_benign": benign_kept,
        "kept_redteam_touching": rt_touch,
        "benign_sample": args.benign_sample,
        "elapsed_seconds": round(elapsed2, 1),
        "parquet_rows": parquet_rows,
        "parquet_row_groups": pf.metadata.num_row_groups,
        "output_file_bytes": out.stat().st_size,
        "output_sha256": _sha256(out),
        "redteam_overlap_ok": overlap_ok,
        "nonempty": bool(parquet_rows > 0),
        "completed": True,
    }
    manifest.write_text(json.dumps(info, indent=2), encoding="utf-8")
    if info["nonempty"] and overlap_ok:
        done_marker.write_text("completed\n", encoding="utf-8")

    print("\n=== compaction summary ===")
    print(f"  scanned raw rows   : {scanned:,}")
    print(f"  kept events        : {parquet_rows:,}  (red-team-touching {rt_touch:,} / benign-sampled {benign_kept:,})")
    print(f"  parquet rows       : {parquet_rows:,}")
    print(f"  retained time range: {t_min} -> {t_max}")
    print(f"  red-team overlap   : {overlap_ok}")
    print(f"  completed (marker) : {done_marker.exists()}")
    print(f"  elapsed            : {elapsed2:.0f}s total")
    print(f"  manifest           : {manifest}")


if __name__ == "__main__":
    main()