# Correlating Authentication Telemetry for Credential-Attack Detection: A Multi-Format Threat Hunting Tool

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2026

*Independent research portfolio, prepared as part of a PhD application in cybersecurity.
Developed with AI coding assistance; all methods, experiments, and findings were
directed, reviewed, and verified by the author.*

## Abstract

Credential-based attacks — brute forcing, password spraying, and the compromise
that follows a successful guess — leave their traces across authentication logs
that rarely share a common schema. A defender pulling SSH history from a Linux host,
Security events from a Windows domain controller, and a normalized export from a SIEM
is looking at three different shapes of the same underlying event. This project is a
small command-line tool that ingests those three formats into one representation and
runs three complementary detectors over it: brute-force counting per source and
account, correlation of a successful login against an immediately preceding run of
failures, and a volume-based flag for source addresses that behave unlike their
peers. The contribution is not a new algorithm; it is a careful, tested
implementation with attention to the failure modes that show up only on real,
multi-format data. During this work I identified and fixed a timestamp-ordering
defect that silently corrupted the success-after-failure correlation on any log
spanning more than one calendar month, and I raised test coverage from two
end-to-end smoke tests (both failing due to an environment portability defect) to a
seventeen-test suite covering each detector in isolation.

## 1. Introduction

Authentication logs are among the highest-value and lowest-cost telemetry a defender
has. A failed logon is cheap to record and, in aggregate, tells a clear story:
sustained failures against one account from one address is a brute-force attempt; a
success that lands after such a run is a plausible compromise; a single address
touching an unusual number of distinct accounts is spraying. None of these require
payload inspection or endpoint agents — only the login record itself.

The practical obstacle is heterogeneity. Linux hosts write SSH outcomes to
`auth.log` as free-text lines (`Failed password for invalid user admin from …`).
Windows records logons as structured events, principally 4624 (success) and 4625
(failure). A SIEM may hand back a tidy CSV with none of that provenance. A hunting
workflow that only speaks one dialect forces the analyst to normalize by hand, which
is exactly the tedium that gets skipped under time pressure.

This tool takes the position that normalization belongs in the tool. It parses all
three formats into a single event frame with the fields `timestamp`, `username`,
`source_ip`, `event_type`, and `status`, then applies format-agnostic detection.

## 2. Related context

The detection ideas here are well established. Brute-force detection by failure
count is the mechanism behind tools such as Fail2ban. The 4624/4625 event pairing is
standard Windows logon monitoring. Volume- and peer-based outlier flagging is a
staple of security analytics. The intent of this project is pedagogical and
practical rather than novel: to build a correct, legible reference implementation
that spans formats, and to treat its correctness as something to be demonstrated with
tests rather than asserted.

## 3. Method

### 3.1 Ingestion and normalization

Input format is either declared (`--format`) or auto-detected from file extension
and, for CSV, column signature. Linux logs are parsed with two regular expressions,
one for `Failed password` and one for `Accepted`, capturing the timestamp, username
(including the `invalid user` case), and source address. Windows CSV exports are
filtered to event IDs 4624 and 4625 and mapped to success/failure. After parsing,
`status` is lower-cased and a real datetime column, `event_time`, is derived from the
raw timestamp string (see §3.3).

### 3.2 Detectors

**Brute force.** Failures are grouped by `(source_ip, username)`; any pair meeting or
exceeding a threshold (default 5) is reported as high severity.

**Success after failures.** For each `(source_ip, username)` group, events are walked
in chronological order, maintaining a running failure count that resets on any
success. A success reached while the running count is at or above the threshold is
reported as a likely post-brute-force compromise. This detector is the one most
sensitive to event ordering.

**Unusual source-IP activity.** Per-source totals — event count and distinct-user
count — are compared against a cutoff of mean plus one population standard deviation.
Sources exceeding either cutoff are flagged at medium severity. Because a single
source has zero standard deviation and therefore a degenerate cutoff, the detector
returns nothing when fewer than two sources are present.

Findings are de-duplicated and ordered by severity for the report, with a JSON
summary and two plots (failed logins per source, findings by type).

### 3.3 A correctness defect in timestamp ordering

The success-after-failures detector depends on walking events in true chronological
order. The original implementation sorted on the raw `timestamp` string. For ISO-8601
CSV timestamps this is safe, because lexical and chronological order coincide. For
Linux syslog timestamps it is not: those carry a month *name* and no year
(`May 10 08:00:01`), so a string sort orders records by the alphabetical order of the
month abbreviation. Concretely, the three timestamps December 1, February 1, and
January 15 sort lexically as *December, February, January* — the reverse of one and
the transposition of the others relative to true time. On any log spanning a month
boundary, the failure run preceding a success could therefore be miscounted, silently
producing false negatives or false positives in the compromise correlation. The
defect was invisible on the bundled sample data because those events fall within a
single morning.

The fix parses timestamps once, at load time, into a datetime column
(`pd.to_datetime(..., errors="coerce")`), and all ordering uses that column.
Year-less syslog timestamps are assumed to fall in the current year, which preserves
correct ordering within a single log file; unparseable values become `NaT` and are
sorted last rather than raising. Recovering the true year across a log-rotation
boundary at the turn of a year remains an open limitation, deliberately not addressed
here.

## 4. Evaluation

Evaluation is functional rather than statistical: the sample corpus is synthetic and
small, so accuracy figures against it would be uninformative. The relevant results
are behavioral consistency and test coverage.

Running the tool across the three bundled formats yields stable, sensible findings:

| Format          | Events | Findings |
|-----------------|:------:|:--------:|
| Normalized CSV  |   19   |    4     |
| Linux `auth.log`|   11   |    3     |
| Windows events  |   10   |    2     |

These counts were recorded before the code changes and reproduced after them,
confirming the fixes altered behavior only on inputs the samples do not exercise
(multi-month logs, malformed Windows rows, single-source data) rather than regressing
the common path.

Test coverage was rebuilt. The pre-existing suite comprised two end-to-end smoke
tests, both of which failed — not on logic, but because they invoked a bare `python`
subprocess that resolved to an interpreter without the project's dependencies. This
is a genuine portability defect: it passes only where `python` on `PATH` happens to
be the right environment. The tests now spawn `sys.executable`, guaranteeing the
subprocess matches the test interpreter, and a third smoke test covers the Windows
format. A new unit suite exercises each detector directly on hand-constructed frames,
including a regression test for the timestamp defect that supplies deliberately
out-of-order month-name timestamps and asserts the correct failure count. The suite
now stands at seventeen tests, all passing.

## 5. Limitations

- The corpus is synthetic; no claim is made about detection rates on real traffic.
- Syslog year inference assumes the current year and does not handle rotation across
  a New Year boundary.
- Detection is count-based, not time-windowed: a slow drip of failures over days is
  scored identically to a burst over seconds.
- Source-IP anomaly flagging relies solely on volume, with no enrichment.

## 6. Future work

The most valuable next step is time-window burst detection, which would separate slow
credential-stuffing from fast brute forcing that a raw count conflates. Beyond that,
enriching source addresses with geolocation or threat-intelligence reputation would
give the volume-based detector corroborating signal, and parsing Windows EVTX
directly rather than via CSV export would remove a manual step from the intended
workflow.

## 7. Conclusion

The engineering value of this pass was less in the detectors, which are conventional,
than in making them trustworthy: finding a timestamp-ordering defect that a
casual read and the sample data both hide, fixing an environment-dependent test
failure, and leaving behind a test suite that pins the corrected behavior. A hunting
tool that is wrong only on inputs its own samples never reach is the most dangerous
kind, because it looks correct. The work here was mostly about closing that gap.
