# Threat Hunting Log Analysis

[![CI](https://github.com/Farooq-Syed/threat-hunting-log-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/Farooq-Syed/threat-hunting-log-analysis/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-non--commercial-purple)

This project analyzes authentication data to identify brute-force behavior, suspicious successful logins after repeated failures, source IPs with unusual activity patterns, dense bursts of failures within a short window, and accounts that start authenticating from a new source - the shape of a replayed credential.

Developed with AI coding assistance; the author chose the log formats, detection
logic, evaluation framing, debugging direction, and final interpretation of the
results.

## Results at a glance

![Results panel](assets/results_panel.png)

Run against a Linux `auth.log`, the tool processes the events, correlates repeated
failures into brute-force findings, and flags the successful login that follows -
catching the attacker at `203.0.113.5` who guessed the `admin` password after five
failures. See [PAPER.md](PAPER.md) for the method and [JOURNAL.md](JOURNAL.md) for the
development notes. For source and technique citations, see
[REFERENCES.md](REFERENCES.md).

It supports five input styles:

- normalized CSV authentication logs
- Linux `auth.log` style SSH events
- Windows Security event exports focused on logon activity
- Windows `.evtx` files directly (via `python-evtx`)
- LANL comprehensive cyber-data authentication records (`--format lanl-auth`)

## LANL enterprise-data path

The parser now accepts the de-identified authentication schema published by Los
Alamos National Laboratory: epoch time, source/destination users, source/destination
computers, authentication and logon types, orientation, and outcome. LANL source
computers are retained as source identifiers in the normalized `source_ip` field so
the existing hunting layer can operate without inventing network addresses.

The parser and locked temporal protocol have now been run on a 314,683,765-event sampled
evaluation frame derived from the official authentication corpus. With day 15 as the split,
the failure-count, burst, and success-after-failure detectors detected none of 86 test-period
red-team events. The lateral detector detected 32/86 (recall 0.3721) but generated 309,704
alerts (precision 0.0001; about 19,357 alerts per represented test day). This is a negative
result: these simple detectors do not provide usable separation on this frame. Full metrics
and caveats are in [REAL_DATA_RESULTS.md](REAL_DATA_RESULTS.md); the locked protocol is in
[PUBLICATION_PLAN.md](PUBLICATION_PLAN.md).

After obtaining the files from LANL, the streaming evaluator avoids loading the full
corpus into memory and records input hashes plus the official DOI:

```powershell
python evaluate_lanl.py --auth auth.txt.gz --redteam redteam.txt.gz `
  --output results/lanl_external_validation.json
```

The online evaluator reports event recall, precision, F1, time-to-detection, raw and per-day
alert burden, and a key-day FPR proxy. Alert burden and the FPR proxy are conditional on the
24-hour-context plus deterministic 5% background frame and must not be presented as
population-wide operational rates.

## Features

- multi-format log ingestion (including `.evtx`)
- brute-force detection by source IP and username
- success-after-failures correlation
- time-window burst detection (dense failures vs. slow drip)
- lateral-movement detection (success from a new source)
- unusual source IP activity detection
- exported findings report, summary, and plots
- lightweight notebook for investigation walkthroughs

## Project Structure

```text
.
|-- log_hunter.py
|-- requirements.txt
|-- .gitignore
|-- data/
|   |-- sample_auth_logs.csv
|   |-- sample_linux_auth.log
|   `-- sample_windows_security_events.csv
|-- assets/
|   |-- failed_logins_by_ip_sample.png
|   `-- findings_by_type_sample.png
`-- notebooks/
    `-- threat_hunting_walkthrough.ipynb
```

## Installation

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run the normalized CSV sample:

```powershell
python log_hunter.py
```

Run a Linux auth log:

```powershell
python log_hunter.py --input data/sample_linux_auth.log --format linux-auth
```

Run a Windows Security event export:

```powershell
python log_hunter.py --input data/sample_windows_security_events.csv --format windows-events
```

Run a Windows `.evtx` file directly:

```powershell
python log_hunter.py --input path\to\Security.evtx --format evtx
```

Tune the burst window (default 5 minutes) or the lateral-movement window (default 24 hours):

```powershell
python log_hunter.py --window-minutes 1 --lateral-window-hours 48
```

## Larger synthetic dataset

The bundled samples are small and hand-built. For a run with more weight,
`generate_auth_logs.py` produces a larger synthetic normalized-CSV log that mixes
normal activity with brute-force and password-spraying bursts. The data is synthetic
(generated user names, IPs, and timing), intended for demonstration rather than as a
benchmark — for real evaluation, point the tool at genuine `auth.log` or Windows
event exports.

```powershell
python generate_auth_logs.py --rows 3000 --output data/synthetic_auth_logs.csv
python log_hunter.py --input data/synthetic_auth_logs.csv --format csv
python evaluate_synthetic_logs.py --input data/synthetic_auth_logs.csv
```

On a 3,000-event run this surfaces on the order of 50 findings across the detectors
(brute force, success-after-failures, burst, lateral movement, and unusual source-IP
activity).

The synthetic generator now carries scenario labels so the project can evaluate more
than "did it run?". On a 3,000-event labeled synthetic run, the current detector
recovers **23/23 brute-force source/user pairs** and **11/11 success-after-failures
compromise pairs** generated by the script.

## Output

The script writes:

- `output/hunting_report.csv`
- `output/summary.json`
- `output/plots/failed_logins_by_ip.png`
- `output/plots/findings_by_type.png`

The synthetic evaluation script writes:

- `output/synthetic_eval_metrics.json`

## Sample Visuals

Failed logins by source IP:

![Failed logins by IP](assets/failed_logins_by_ip_sample.png)

Findings by type:

![Findings by type](assets/findings_by_type_sample.png)

## Real-World Notes

This project is designed around common authentication telemetry:

- Linux SSH failures often appear in `auth.log` as `Failed password` and `Accepted password` records
- Windows logon monitoring commonly uses Security events `4624` for successful logons and `4625` for failed logons

## Next Steps

- ~~add time-window based burst detection~~ - done
- ~~parse EVTX directly instead of CSV exports~~ - done
- enrich source IPs with geo or threat intel
- treat the detectors as a small ensemble with explicit reasoning about which alert to look at first
- add a notebook for Windows-specific investigation examples

## Authorship and AI use

- The project framing, detection rules, and claims are the author's.
- AI assistance was used for coding support and drafting help.
- The author reviewed, edited, tested, and verified the final code and write-up.
