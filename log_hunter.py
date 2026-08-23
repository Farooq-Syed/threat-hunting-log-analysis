"""
Threat hunting log analysis project.

Supported input formats:
- normalized CSV authentication logs
- Linux auth.log style SSH records
- Windows Security event exports focused on 4624/4625 logon events
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import matplotlib

# Use a non-interactive backend so plotting works on headless machines and CI.
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402  (import after backend selection)
import pandas as pd


DEFAULT_INPUT = "data/sample_auth_logs.csv"
DEFAULT_OUTPUT = "output/hunting_report.csv"
DEFAULT_SUMMARY = "output/summary.json"
DEFAULT_PLOT_DIR = "output/plots"

LINUX_FAILED_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).+sshd\[\d+\]: Failed password for (invalid user )?(?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)
LINUX_SUCCESS_PATTERN = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).+sshd\[\d+\]: Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze authentication logs for suspicious behavior.")
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Path to the input log file.")
    parser.add_argument("--format", default="auto", choices=["auto", "csv", "linux-auth", "windows-events", "evtx", "lanl-auth"], help="Input format.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Path to write the hunting report CSV.")
    parser.add_argument("--summary", default=DEFAULT_SUMMARY, help="Path to write the JSON summary.")
    parser.add_argument("--plot-dir", default=DEFAULT_PLOT_DIR, help="Directory for output plots.")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Failed login threshold for brute-force detection.")
    parser.add_argument("--window-minutes", type=int, default=5, help="Width of the time window for burst detection.")
    parser.add_argument("--lateral-window-hours", type=int, default=24, help="Hours within which a change of source IP is treated as possible lateral movement.")
    parser.add_argument("--agreement-output", default="", help="Optional path to write cross-detector agreement JSON.")
    return parser


def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        return "evtx"
    if suffix == ".log":
        return "linux-auth"
    if suffix == ".csv":
        sample = pd.read_csv(path, nrows=5)
        columns = set(sample.columns)
        if {"timestamp", "username", "source_ip", "event_type", "status"}.issubset(columns):
            return "csv"
        if {"EventID", "TargetUserName", "IpAddress"}.issubset(columns):
            return "windows-events"
    raise ValueError("Could not detect the log format automatically. Use --format explicitly.")


def load_logs(path: Path, input_format: str) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    resolved_format = detect_format(path) if input_format == "auto" else input_format

    if resolved_format == "csv":
        dataframe = pd.read_csv(path)
    elif resolved_format == "linux-auth":
        dataframe = parse_linux_auth_log(path)
    elif resolved_format == "windows-events":
        dataframe = parse_windows_events_csv(path)
    elif resolved_format == "evtx":
        dataframe = parse_evtx(path)
    elif resolved_format == "lanl-auth":
        dataframe = parse_lanl_auth(path)
    else:
        raise ValueError(f"Unsupported format: {resolved_format}")

    if dataframe.empty:
        raise ValueError("The input log file produced no usable events.")

    required_columns = {"timestamp", "username", "source_ip", "event_type", "status"}
    missing = required_columns - set(dataframe.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    # Normalise status early so every downstream check can rely on it.
    dataframe["status"] = dataframe["status"].astype(str).str.strip().str.lower()

    # Parse timestamps into a real datetime column used for ordering. Chronological
    # ordering matters for the success-after-failures correlation: sorting the raw
    # syslog strings sorts them lexically ("Dec" < "Feb" < "Jan"), which is wrong.
    dataframe["event_time"] = parse_timestamps(dataframe["timestamp"])

    return dataframe


def parse_timestamps(values: pd.Series) -> pd.Series:
    """Best-effort parse of the mixed timestamp formats this tool ingests.

    Handles ISO CSV timestamps and Windows TimeCreated directly. Linux syslog
    timestamps ("May 10 08:00:01") carry no year, so pandas assumes the current
    one, which keeps ordering within a single log correct. Anything unparseable
    falls back to NaT and is sorted last rather than crashing the run.
    """
    parsed = pd.to_datetime(values, errors="coerce", format="mixed")
    if parsed.isna().all():
        # Older pandas without format="mixed" support, or an exotic format.
        parsed = pd.to_datetime(values, errors="coerce")
    return parsed


def parse_linux_auth_log(path: Path) -> pd.DataFrame:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        failed_match = LINUX_FAILED_PATTERN.match(line)
        if failed_match:
            rows.append(
                {
                    "timestamp": failed_match.group("timestamp"),
                    "username": failed_match.group("username"),
                    "source_ip": failed_match.group("source_ip"),
                    "event_type": "ssh_login",
                    "status": "failed",
                }
            )
            continue

        success_match = LINUX_SUCCESS_PATTERN.match(line)
        if success_match:
            rows.append(
                {
                    "timestamp": success_match.group("timestamp"),
                    "username": success_match.group("username"),
                    "source_ip": success_match.group("source_ip"),
                    "event_type": "ssh_login",
                    "status": "success",
                }
            )
    return pd.DataFrame(rows)


def parse_lanl_auth(path: Path) -> pd.DataFrame:
    """Parse LANL comprehensive cyber-data authentication records.

    The official schema is:
    time,source user,destination user,source computer,destination computer,
    authentication type,logon type,orientation,success/failure.

    LANL identifiers are de-identified host names rather than IP addresses. They
    are retained in ``source_ip`` so the existing detector layer can operate on
    a stable source-identifier field without special cases.
    """
    rows = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for fields in csv.reader(handle):
            if len(fields) != 9:
                continue
            try:
                epoch_seconds = int(fields[0])
            except ValueError:
                continue
            outcome = fields[8].strip().lower()
            if outcome not in {"success", "failure"}:
                continue
            rows.append(
                {
                    "timestamp": pd.to_datetime(epoch_seconds, unit="s", utc=True).isoformat(),
                    "username": fields[1].strip() or "unknown",
                    "source_ip": fields[3].strip() or "unknown",
                    "destination": fields[4].strip() or "unknown",
                    "event_type": "lanl_authentication",
                    "status": "success" if outcome == "success" else "failed",
                }
            )
    return pd.DataFrame(rows)


def parse_windows_events_csv(path: Path) -> pd.DataFrame:
    dataframe = pd.read_csv(path)
    rows = []
    for _, row in dataframe.iterrows():
        event_id = _coerce_event_id(row.get("EventID"))
        if event_id not in {4624, 4625}:
            continue
        username = _first_present(row, ["TargetUserName", "AccountName"], default="unknown")
        source_ip = _first_present(row, ["IpAddress", "SourceNetworkAddress"], default="unknown")
        rows.append(
            {
                "timestamp": _first_present(row, ["TimeCreated", "timestamp"], default=""),
                "username": username,
                "source_ip": source_ip,
                "event_type": "windows_logon",
                "status": "success" if event_id == 4624 else "failed",
            }
        )
    return pd.DataFrame(rows)


def _coerce_event_id(value: object) -> int:
    """Return the event id as an int, or -1 for blank/non-numeric cells.

    Windows exports occasionally contain rows with an empty or malformed EventID
    (trailing blank lines, merged exports). A bare int() would raise; here such
    rows simply fail the {4624, 4625} membership test and are skipped.
    """
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return -1


def _first_present(row: pd.Series, columns: list[str], default: str) -> str:
    """First non-empty value across candidate columns, else the default.

    Unlike Series.get(col, fallback), this treats NaN/empty strings as absent, so
    a present-but-null TargetUserName correctly falls through to AccountName.
    """
    for column in columns:
        if column in row.index:
            value = row[column]
            if pd.notna(value) and str(value).strip():
                return str(value).strip()
    return default


def parse_evtx(path: Path) -> pd.DataFrame:
    """Parse a Windows EVTX log for logon events (4624 success / 4625 failure).

    The binary container is read with python-evtx; each record is a small XML
    document that is then converted with parse_evtx_record_xml, which is pure and
    unit-tested in isolation. The dependency is optional in the sense that this
    function imports it lazily and reports a clear message when it is missing.
    """
    try:
        from Evtx.Evtx import Evtx
    except ImportError as error:
        raise ImportError(
            "Parsing .evtx files requires the 'python-evtx' package. "
            "Install it with: python -m pip install python-evtx"
        ) from error

    rows = []
    with Evtx(str(path)) as log:
        for record in log.records():
            rows.append(parse_evtx_record_xml(record.xml()))
    return pd.DataFrame(rows)


def parse_evtx_record_xml(xml_text: str) -> dict:
    """Convert one EVTX record's XML into the tool's event schema.

    Iteration is namespaces-agnostic on purpose: EVTX records carry a default
    XML namespace that varies across Windows versions and export tooling, and a
    fixed namespace prefix would silently match nothing on real files.
    """
    root = ET.fromstring(xml_text)
    event_id = -1
    timestamp = ""
    username = ""
    source_ip = ""

    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]  # strip any namespace prefix
        if tag == "EventID":
            event_id = _coerce_event_id(element.text)
        elif tag == "TimeCreated":
            timestamp = element.get("SystemTime", "")
        elif tag == "Data":
            name = (element.get("Name") or "").lower()
            value = (element.text or "").strip()
            if name in {"targetusername", "accountname"} and not username:
                username = value
            elif name in {"ipaddress", "sourceip", "ip"} and not source_ip:
                source_ip = value

    if event_id not in {4624, 4625}:
        return {
            "timestamp": timestamp,
            "username": "unknown",
            "source_ip": "unknown",
            "event_type": "windows_logon",
            "status": "skipped",
        }

    return {
        "timestamp": timestamp,
        "username": username or "unknown",
        "source_ip": source_ip or "unknown",
        "event_type": "windows_logon",
        "status": "success" if event_id == 4624 else "failed",
    }


def detect_bruteforce(dataframe: pd.DataFrame, threshold: int) -> pd.DataFrame:
    failures = dataframe[dataframe["status"] == "failed"].copy()
    if failures.empty:
        return pd.DataFrame(columns=["source_ip", "username", "failed_attempts"])
    counts = failures.groupby(["source_ip", "username"]).size().reset_index(name="failed_attempts")
    return counts[counts["failed_attempts"] >= threshold]


def detect_success_after_failures(dataframe: pd.DataFrame, threshold: int) -> pd.DataFrame:
    suspicious_rows = []
    for (source_ip, username), group in dataframe.groupby(["source_ip", "username"]):
        # Sort chronologically by the parsed datetime, not the raw string. NaT
        # timestamps sort last so undated rows do not reorder dated ones.
        group = group.sort_values("event_time", na_position="last")
        failed_count = 0
        for _, row in group.iterrows():
            status = str(row["status"]).lower()
            if status == "failed":
                failed_count += 1
            elif status == "success" and failed_count >= threshold:
                suspicious_rows.append(
                    {
                        "timestamp": row["timestamp"],
                        "username": username,
                        "source_ip": source_ip,
                        "details": f"{failed_count} failed attempts before success",
                    }
                )
                break
            elif status == "success":
                failed_count = 0
    return pd.DataFrame(suspicious_rows)


def detect_unusual_ip_activity(dataframe: pd.DataFrame) -> pd.DataFrame:
    activity = (
        dataframe.groupby("source_ip")
        .agg(
            total_events=("source_ip", "size"),
            unique_users=("username", "nunique"),
            failed_attempts=("status", lambda values: sum(str(v).lower() == "failed" for v in values)),
        )
        .reset_index()
    )
    # A single source IP has zero standard deviation, so the cutoff collapses to
    # the value itself and nothing is ever "unusual". Skip in that degenerate case.
    if len(activity) < 2:
        return activity.iloc[0:0].copy()
    event_cutoff = activity["total_events"].mean() + activity["total_events"].std(ddof=0)
    user_cutoff = activity["unique_users"].mean() + activity["unique_users"].std(ddof=0)
    return activity[(activity["total_events"] > event_cutoff) | (activity["unique_users"] > user_cutoff)].copy()


def detect_burst_activity(dataframe: pd.DataFrame, window_minutes: int, min_failures: int) -> pd.DataFrame:
    """Flag source IPs with a dense run of failures inside a short time window.

    The count-based brute-force detector treats a slow drip of five failures over
    two days identically to five failures in a minute. This detector separates the
    two: for each source it walks its failures in time order and measures how many
    fall inside a trailing window of window_minutes. A source whose peak window
    reaches min_failures is reported once, at its densest moment.
    """
    failures = dataframe[dataframe["status"] == "failed"]
    if failures.empty:
        return pd.DataFrame(columns=["source_ip", "event_time", "peak_failures"])
    cutoff = pd.Timedelta(minutes=window_minutes)

    records = []
    for source_ip, group in failures.groupby("source_ip"):
        times = group["event_time"].sort_values().to_numpy()
        for index, current in enumerate(times):
            if pd.isna(current):
                continue
            window_start = current - cutoff
            in_window = (times >= window_start) & (times <= current)
            records.append((source_ip, current, int(in_window.sum())))

    bursts = pd.DataFrame(records, columns=["source_ip", "event_time", "failures_in_window"])
    bursts = bursts[bursts["failures_in_window"] >= min_failures]
    if bursts.empty:
        return pd.DataFrame(columns=["source_ip", "event_time", "peak_failures"])
    best = bursts.loc[bursts.groupby("source_ip")["failures_in_window"].idxmax()]
    best = best.rename(columns={"failures_in_window": "peak_failures"}).reset_index(drop=True)
    return best[["source_ip", "event_time", "peak_failures"]]


def detect_lateral_movement(dataframe: pd.DataFrame, window_hours: int) -> pd.DataFrame:
    """Flag accounts that authenticate successfully from a new source after a prior one.

    A successful logon from one address followed, within window_hours, by another
    successful logon from a different address for the same account is the classic
    shape of a compromised credential being replayed from a second host. Only
    distinct consecutive successes are compared, so a user who alternates between
    two known IPs in the normal course of work is reported at most once per pair.
    """
    successes = dataframe[dataframe["status"] == "success"]
    if successes.empty:
        return pd.DataFrame(columns=["timestamp", "username", "source_ip", "details"])

    cutoff = pd.Timedelta(hours=window_hours)
    findings = []
    for username, group in successes.groupby("username"):
        group = group.sort_values("event_time")
        history: list[tuple] = []
        for row in group.itertuples():
            if pd.isna(row.event_time):
                continue
            history.append((row.event_time, row.source_ip, row.timestamp))
        for index in range(1, len(history)):
            previous_time, previous_ip, _ = history[index - 1]
            current_time, current_ip, current_stamp = history[index]
            if previous_ip != current_ip and (current_time - previous_time) <= cutoff:
                findings.append(
                    {
                        "timestamp": current_stamp,
                        "username": username,
                        "source_ip": current_ip,
                        "details": f"previously authenticated from {previous_ip}",
                    }
                )
                break
    return pd.DataFrame(findings)


def build_report(dataframe: pd.DataFrame, failed_threshold: int, window_minutes: int = 5, lateral_window_hours: int = 24) -> pd.DataFrame:
    brute_force = detect_bruteforce(dataframe, failed_threshold)
    success_after_failures = detect_success_after_failures(dataframe, failed_threshold)
    unusual_ip_activity = detect_unusual_ip_activity(dataframe)
    burst_activity = detect_burst_activity(dataframe, window_minutes, failed_threshold)
    lateral_movement = detect_lateral_movement(dataframe, lateral_window_hours)

    findings = []
    for _, row in brute_force.iterrows():
        findings.append(
            {
                "finding_type": "brute_force_attempt",
                "source_ip": row["source_ip"],
                "username": row["username"],
                "severity": "high",
                "details": f"{int(row['failed_attempts'])} failed login attempts",
            }
        )

    for _, row in success_after_failures.iterrows():
        findings.append(
            {
                "finding_type": "successful_login_after_failures",
                "source_ip": row["source_ip"],
                "username": row["username"],
                "severity": "high",
                "details": row["details"],
            }
        )

    for _, row in burst_activity.iterrows():
        findings.append(
            {
                "finding_type": "burst_brute_force",
                "source_ip": row["source_ip"],
                "username": "multiple",
                "severity": "high",
                "details": f"{int(row['peak_failures'])} failed logins within {window_minutes} minutes",
            }
        )

    for _, row in lateral_movement.iterrows():
        findings.append(
            {
                "finding_type": "lateral_movement",
                "source_ip": row["source_ip"],
                "username": row["username"],
                "severity": "high",
                "details": row["details"],
            }
        )

    for _, row in unusual_ip_activity.iterrows():
        findings.append(
            {
                "finding_type": "unusual_source_ip_activity",
                "source_ip": row["source_ip"],
                "username": "multiple",
                "severity": "medium",
                "details": f"{int(row['total_events'])} events across {int(row['unique_users'])} users",
            }
        )

    if not findings:
        return pd.DataFrame(columns=["finding_type", "source_ip", "username", "severity", "details"])

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    report = pd.DataFrame(findings).drop_duplicates()
    report["severity_rank"] = report["severity"].map(severity_rank)
    report = report.sort_values(["severity_rank", "source_ip"]).drop(columns=["severity_rank"]).reset_index(drop=True)
    return report


def detector_agreement(dataframe: pd.DataFrame, failed_threshold: int,
                       window_minutes: int = 5, lateral_window_hours: int = 24) -> dict:
    """Measure how much the detectors agree, per source IP.

    Each detector keys on a different unit (some on a source:user pair, some on a
    source IP, one on a username). To compare them we lift every detector's output to
    the source-IP level and ask: how often do two detectors flag the same IP, and how
    often do they disagree? High pairwise overlap means the signals are redundant; low
    overlap means the detectors are genuinely complementary (e.g. a slow-drip brute
    force that the count detector sees but the burst detector does not). That
    disagreement is the reason to treat them as an ensemble rather than a single alert.
    """
    def _ips(result: pd.DataFrame) -> set:
        if result.empty or "source_ip" not in result.columns:
            return set()
        return set(result["source_ip"].astype(str))

    flagged: dict[str, set] = {
        "bruteforce": _ips(detect_bruteforce(dataframe, failed_threshold)),
        "success_after_failures": _ips(detect_success_after_failures(dataframe, failed_threshold)),
        "burst": _ips(detect_burst_activity(dataframe, window_minutes, failed_threshold)),
        "lateral": _ips(detect_lateral_movement(dataframe, lateral_window_hours)),
        "unusual_ip": _ips(detect_unusual_ip_activity(dataframe)),
    }
    all_ips = sorted(set().union(*flagged.values()))
    names = list(flagged)

    pairwise = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            inter = len(flagged[a] & flagged[b])
            union = len(flagged[a] | flagged[b])
            left = len(flagged[a])
            right = len(flagged[b])
            denominator = min(left, right)
            pairwise.append({
                "detector_a": a,
                "detector_b": b,
                "shared_ips": inter,
                "jaccard": round(inter / union, 3) if union else 0.0,
                "coflag_rate": round(inter / denominator, 3) if denominator else 0.0,
                "a_flagged": left,
                "b_flagged": right,
            })

    flagged_count = sum(1 for ip in all_ips if sum(ip in s for s in flagged.values()) == 1)
    coflagged = sum(1 for ip in all_ips if sum(ip in s for s in flagged.values()) >= 2)

    return {
        "per_detector_flagged_ips": {name: len(flagged[name]) for name in names},
        "total_distinct_ips_flagged": len(all_ips),
        "ips_flagged_by_1_detector_only": flagged_count,
        "ips_flagged_by_2_or_more": coflagged,
        "pairwise": pairwise,
    }


def save_summary(report: pd.DataFrame, summary_path: Path) -> None:
    summary = {
        "findings_count": int(len(report)),
        "high_severity_findings": int((report["severity"] == "high").sum()) if not report.empty else 0,
        "finding_types": report["finding_type"].value_counts().to_dict() if not report.empty else {},
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


def generate_plots(dataframe: pd.DataFrame, report: pd.DataFrame, plot_dir: Path) -> None:
    plot_dir.mkdir(parents=True, exist_ok=True)
    plt.style.use("ggplot")

    failed_counts = dataframe[dataframe["status"] == "failed"].groupby("source_ip").size().sort_values(ascending=False).head(8)
    fig, ax = plt.subplots(figsize=(9, 5))
    failed_counts.plot(kind="bar", ax=ax, color="#c1121f")
    ax.set_title("Top Source IPs by Failed Logins")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Failed Logins")
    fig.tight_layout()
    fig.savefig(plot_dir / "failed_logins_by_ip.png", dpi=180)
    plt.close(fig)

    if not report.empty:
        counts = report["finding_type"].value_counts()
        fig, ax = plt.subplots(figsize=(9, 5))
        counts.plot(kind="bar", ax=ax, color="#1d3557")
        ax.set_title("Threat Hunting Findings by Type")
        ax.set_xlabel("Finding Type")
        ax.set_ylabel("Count")
        fig.tight_layout()
        fig.savefig(plot_dir / "findings_by_type.png", dpi=180)
        plt.close(fig)


def main() -> None:
    args = build_parser().parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)
    plot_dir = Path(args.plot_dir)

    dataframe = load_logs(input_path, args.format)
    report = build_report(dataframe, args.failed_threshold, args.window_minutes, args.lateral_window_hours)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_path, index=False)
    save_summary(report, summary_path)
    generate_plots(dataframe, report, plot_dir)

    print(f"Processed {len(dataframe)} log events.")
    print(f"Generated {len(report)} findings.")
    print(f"Report written to: {output_path}")
    print(f"Summary written to: {summary_path}")
    print(f"Plots written to: {plot_dir}")

    if args.agreement_output:
        agreement = detector_agreement(dataframe, args.failed_threshold, args.window_minutes, args.lateral_window_hours)
        agreement_path = Path(args.agreement_output)
        agreement_path.parent.mkdir(parents=True, exist_ok=True)
        agreement_path.write_text(json.dumps(agreement, indent=2), encoding="utf-8")
        print(f"Agreement written to: {agreement_path}")


if __name__ == "__main__":
    main()
