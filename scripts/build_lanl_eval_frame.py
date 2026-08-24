"""Build a small, documented evaluation frame from the compact LANL auth parquet.

The compact corpus (374M events) is too large for in-memory evaluation on modest hardware.
This script produces a **sampled evaluation frame** that preserves what the detectors and the
ground truth need while keeping the file small enough to evaluate. The reduction is explicit
and defensible (per PUBLICATION_PLAN Phase 2 §2.3 / the sampled-frame policy):

  1. **All red-team-relevant context**: every event whose time is within ``context_hours``
     (default 24 h) of *any* red-team event. This keeps the malicious sequences intact.
  2. **A fixed-rate sample of the rest**, stratified by (day, src_user, src_computer): for each
     (day, key) stratum we keep a deterministic fraction ``keep_frac`` of its events so the
     benign background and its per-host-day structure remain represented.
  3. Exact inclusion counts and sampling rates are recorded in the manifest, and the output
     is written in bounded memory (batched streaming to parquet row groups).

CRITICAL framing: this is a *sampled evaluation frame*. Alert-burden / false-positive-per-
host-day estimates are conditional on the sampled frame; they are not population-wide unless
sampling weights are applied. Recall is measured against the full red-team ground truth, which
is never subsampled.

Usage:
  python scripts/build_lanl_eval_frame.py --input data/lanl_auth_window.parquet \
      --redteam <redteam>.gz --context-hours 24 --keep-frac 0.05 \
      --output data/lanl_eval_frame.parquet
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

DAY_SECONDS = 86400


def _redteam_times_and_scope(path: Path) -> tuple[list[int], set[str], set[str]]:
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
            users.add(row[1].strip())
            computers.add(row[2].strip())
            computers.add(row[3].strip())
    if not times:
        raise ValueError("no usable red-team events")
    return times, users, computers


def _in_context(t: int, rt_times: list[int], context_s: int) -> bool:
    lo = t - context_s
    hi = t + context_s
    # rt_times are sorted; binary search for any rt within [lo, hi].
    import bisect

    i = bisect.bisect_left(rt_times, lo)
    return i < len(rt_times) and rt_times[i] <= hi


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a documented sampled evaluation frame.")
    ap.add_argument("--input", default="data/lanl_auth_window.parquet")
    ap.add_argument("--redteam", required=True)
    ap.add_argument("--context-hours", type=float, default=24.0)
    ap.add_argument("--keep-frac", type=float, default=0.05,
                    help="Fraction of non-context events kept per (day,key) stratum.")
    ap.add_argument("--output", default="data/lanl_eval_frame.parquet")
    ap.add_argument("--batch", type=int, default=5_000_000)
    args = ap.parse_args()

    rt_times, rt_users, rt_computers = _redteam_times_and_scope(Path(args.redteam))
    rt_times.sort()
    context_s = int(args.context_hours * 3600)
    start = time.time()

    in_path = Path(args.input)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = Path(str(out_path) + ".tmp")

    cols = ["time", "src_user", "dst_user", "src_computer", "dst_computer",
            "auth_type", "logon_type", "status", "is_redteam_touching"]
    writer = None
    total_scanned = 0
    kept_context = 0
    kept_sampled = 0

    pf = pq.ParquetFile(in_path)
    for batch in pf.iter_batches(batch_size=args.batch, columns=cols):
        tbl = pa.Table.from_batches([batch]).to_pandas()
        times = tbl["time"].to_numpy()
        in_ctx = np_is_in_context(times, rt_times, context_s)
        # Vectorized stratified sample of the rest: deterministic hash on (stratum, global row)
        # keep_fraction gate, no per-row Python loop.
        day_key = tbl["time"] // DAY_SECONDS
        stratum_hash = (tbl["src_user"].astype(str) + "\x01" + tbl["src_computer"].astype(str)).map(
            lambda s: _fnv1a(s)).to_numpy(dtype=np.uint64)
        keep = np.zeros(len(tbl), dtype=bool)
        keep[in_ctx] = True
        gate = ((stratum_hash + day_key * 1000003) % 10000) / 10000.0
        sampled = (~in_ctx) & (gate < args.keep_frac)
        keep[sampled] = True
        kept_context += int(keep[in_ctx].sum())
        kept_sampled += int(sampled.sum())
        sub = tbl[keep]
        if len(sub):
            table = pa.Table.from_pandas(sub, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(tmp_out, table.schema)
            writer.write_table(table)
        total_scanned += len(tbl)
    if writer is not None:
        writer.close()
    # Atomic rename only on success
    if tmp_out.exists():
        tmp_out.replace(out_path)

    # manifest with exact inclusion counts and rates
    info = {
        "input": str(in_path),
        "redteam_events": len(rt_times),
        "context_hours": args.context_hours,
        "context_seconds": context_s,
        "keep_frac": args.keep_frac,
        "scanned": int(total_scanned),
        "kept_context": int(kept_context),
        "kept_sampled": int(kept_sampled),
        "output_file_bytes": out_path.stat().st_size,
        "output_sha256": _sha256(out_path),
        "elapsed_seconds": round(time.time() - start, 1),
        "sampling_note": (
            "Sampled evaluation frame: all red-team context kept; non-context events sampled "
            "per (day,key) at keep_frac via a deterministic FNV-1a hash gate. Alert-burden and "
            "false-positive-per-host-day estimates are CONDITIONAL on this frame, not "
            "population-wide unless sampling weights are applied. Red-team ground truth is "
            "never subsampled."
        ),
        "completed": True,
    }
    manifest_path = Path(str(out_path) + ".manifest.json")
    manifest_path.write_text(json.dumps(info, indent=2), encoding="utf-8")
    Path(str(out_path) + ".done").write_text("completed\n", encoding="utf-8")

    print(f"scanned {total_scanned:,} -> kept context {kept_context:,}, sampled {kept_sampled:,} "
          f"({args.keep_frac:.0%} of non-context)")
    print(f"wrote -> {out_path} ({info['output_file_bytes']/1e6:.1f} MB)")
    print("NOTE: alert-burden estimates are conditional on the sampled frame.")


def np_is_in_context(times, rt_times, context_s):
    import numpy as np

    rt = np.asarray(rt_times)
    lo = times - context_s
    hi = times + context_s
    # For each event, any rt in [lo,hi]? Use searchsorted.
    left = np.searchsorted(rt, lo, side="left")
    right = np.searchsorted(rt, hi, side="right")
    return right > left


def _fnv1a(s: str) -> int:
    """FNV-1a 64-bit hash of a string (deterministic across runs and processes)."""
    h = 14695981039346656037
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    main()