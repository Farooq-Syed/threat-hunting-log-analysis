"""
Threat hunting log analysis project.

Supported input formats:
- normalized CSV authentication logs
- Linux auth.log style SSH records
- Windows Security event exports focused on 4624/4625 logon events
"""

from __future__ import annotations

import argparse
import json
import re
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
    parser.add_argument("--format", default="auto", choices=["auto", "csv", "linux-auth", "windows-events"], help="Input format.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Path to write the hunting report CSV.")
    parser.add_argument("--summary", default=DEFAULT_SUMMARY, help="Path to write the JSON summary.")
    parser.add_argument("--plot-dir", default=DEFAULT_PLOT_DIR, help="Directory for output plots.")
    parser.add_argument("--failed-threshold", type=int, default=5, help="Failed login threshold for brute-force detection.")
    return parser


def detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
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


def build_report(dataframe: pd.DataFrame, failed_threshold: int) -> pd.DataFrame:
    brute_force = detect_bruteforce(dataframe, failed_threshold)
    success_after_failures = detect_success_after_failures(dataframe, failed_threshold)
    unusual_ip_activity = detect_unusual_ip_activity(dataframe)

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
    report = build_report(dataframe, args.failed_threshold)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report.to_csv(output_path, index=False)
    save_summary(report, summary_path)
    generate_plots(dataframe, report, plot_dir)

    print(f"Processed {len(dataframe)} log events.")
    print(f"Generated {len(report)} findings.")
    print(f"Report written to: {output_path}")
    print(f"Summary written to: {summary_path}")
    print(f"Plots written to: {plot_dir}")


if __name__ == "__main__":
    main()
