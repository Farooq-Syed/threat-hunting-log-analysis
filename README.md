# Threat Hunting Log Analysis

[![CI](https://github.com/Farooq-Syed/threat-hunting-log-analysis/actions/workflows/ci.yml/badge.svg)](https://github.com/Farooq-Syed/threat-hunting-log-analysis/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

This project analyzes authentication data to identify brute-force behavior, suspicious successful logins after repeated failures, source IPs with unusual activity patterns, dense bursts of failures within a short window, and accounts that start authenticating from a new source - the shape of a replayed credential.

## Results at a glance

![Results panel](assets/results_panel.png)

Run against a Linux `auth.log`, the tool processes the events, correlates repeated
failures into brute-force findings, and flags the successful login that follows -
catching the attacker at `203.0.113.5` who guessed the `admin` password after five
failures. See [PAPER.md](PAPER.md) for the method and [JOURNAL.md](JOURNAL.md) for the
development notes.

It supports four input styles:

- normalized CSV authentication logs
- Linux `auth.log` style SSH events
- Windows Security event exports focused on logon activity
- Windows `.evtx` files directly (via `python-evtx`)

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
```

On a 3,000-event run this surfaces on the order of 50 findings across the detectors
(brute force, success-after-failures, burst, lateral movement, and unusual source-IP
activity).

## Output

The script writes:

- `output/hunting_report.csv`
- `output/summary.json`
- `output/plots/failed_logins_by_ip.png`
- `output/plots/findings_by_type.png`

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
