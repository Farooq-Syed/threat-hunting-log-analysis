# LANL Acquisition Checklist

How to obtain the LANL authentication corpus needed for THLA Phases 3-4. This is a **manual,
human step** — the dataset is distributed through a data-request form, not a public link. The
tool's evaluator (`evaluate_lanl.py`) is ready to consume it once the files are in place.

## Dataset

- **Name:** Comprehensive, Multi-Source Cyber-Security Events (LANL cyber1).
- **What it is:** 58 days of de-identified enterprise event data from five sources at Los
  Alamos National Laboratory — authentication (both endpoint and Active Directory domain
  controllers), process start/stop, DNS, netflow, and a labeled **red-team ground-truth** set
  that defines the positive (attack) class.
- **Size:** ~12 GB compressed across the five elements; the **auth file alone is ~7.2 GB**.
- **Access page:** https://csr.lanl.gov/data/cyber1/
- **Citation / DOI:** the dataset is cited as K. Kent, Comprehensive, Multi-Source Cyber-Security
  Events, Los Alamos National Laboratory, DOI 10.17021/1179829.

## Access terms

- Distributed via the LANL data-request **form** (not a direct download URL). Fill the form with
  your name, affiliation, email, and intended research use.
- Review the LANL **data-use terms**: the data is de-identified and for research; confirm whether
  redistribution or re-publication is permitted before committing the corpus to a public
  repository. **Recommendation:** keep the raw corpus out of git and reference it by path +
  SHA-256, so only the derived results are shared.

## What to download (the two files THLA needs)

| File | Role |
|---|---|
| `auth.txt` (or `auth.txt.gz`) | ~7.2 GB authentication events (the detector input). |
| `redteam.txt` (or `redteam.txt.gz`) | The red-team ground truth (the positive-class labels). |

(The process/DNS/netflow elements are part of the full dataset but are **not** required by the
current THLA experiment, which is authentication-only.)

## Post-download steps

1. **Verify integrity.** Compute `SHA-256` of the exact files you will run:
   ```powershell
   Get-FileHash auth.txt.gz -Algorithm SHA256
   ```
   Record these in the evaluation manifest (written by `evaluate_lanl.py`).
2. **Place the files** somewhere outside the repo (e.g. `D:\datasets\LANL\`), to keep the 12 GB
   out of git. The repo already gitignores data/real/ if you prefer to stage there.
3. **Preliminary schema check** (small, non-memory-heavy): confirm the auth file columns are the
   LANL 9-column format the parser expects.
   ```powershell
   # peek at the first few decompressed lines
   python -c "import gzip; f=gzip.open('auth.txt.gz','rt'); [print(next(f).strip()) for _ in range(3)]"
   ```

## Measured corpus scale (this project's files)

| File | Count | Single-pass time (this machine) |
|---|---|---|
| `auth.txt.gz` | **1,051,430,459 lines** | > 20 min, out-of-memory — **not runnable inline** |
| `redteam.txt.gz` | 749 events / 104 users (epoch 150,885 - 2,557,047, i.e. days ~1.7-29.6) | instant |
| `dns.txt.gz` | 40.8M rows | ~34 s (fast) |
| `proc.txt.gz` | >=40M rows (2.2 GB) | ~31 s (fast) |
| `flows.txt.gz` | 1.0 GB | untested |

**Ground-truth scope (critical).** The official LANL `redteam.txt.gz` is defined **only for the
authentication source** (`time, user, source_computer, destination_computer`). There is no
separate DNS / process / flow ground-truth file in the release. Therefore the only
scientifically valid real-data experiment in this project is on the **authentication corpus**.

**Compute requirement.** The 1.05 B auth rows mean a full streaming parse is only feasible on a
machine with substantial RAM and/or a long wall-clock budget (the compact pass alone needs to
parse and filter ~1 B rows; the raw byte-count took 185 s, `int()`-per-line took > 9 min, and
holding the windowed subset in a Python list was out-of-memory). A `scripts/compact_lanl_auth.py`
is provided that streams and writes a windowed parquet in chunks; it must be run to completion
in an environment that can sustain a 7.2 GB gzip pass (several GB RAM free, ~20-40 min). The
downstream Phase 3-4 evaluation then reads only the compact parquet and is fast.

## Run the streaming evaluator

```powershell
# Streaming; never loads the 7.2 GB file into memory.
python evaluate_lanl.py --auth D:\datasets\LANL\auth.txt.gz \
    --redteam D:\datasets\LANL\redteam.txt.gz \
    --window-hours 24 --output results/lanl_external_validation.json
```

`evaluate_lanl.py` writes: auth-row count, the SHA-256 content digest, the exact ground-truth
event/pair counts, exact-match cover, targeted-lateral candidates, and a
recall/precision bounded to red-team users (this is a *candidate* measure, not a global
false-positive rate). The Phase 3 metric runner (built when the corpus is available) extends
this with alerts-per-day, time-to-detection, and per-host/campaign breakdowns.

## What to do if access is denied or slow

- RETRY/email the LANL point of contact and state the research use clearly.
- If the full 7.2 GB auth corpus is not obtainable in time, the fallback is a **smaller, public,
  labeled auth dataset** — but the paper must then state explicitly that it is not the LANL
  corpus and that campaign/temporal hold-out assumptions differ. That is a weaker evidence base
  and should not be claimed as LANL-level.
