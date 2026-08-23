# Credential-Attack Detection across Authentication Logs: What a Tool for Three Log Formats Taught Me

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2023

*Independent research portfolio, prepared as part of a PhD application in cybersecurity.
Developed with AI coding assistance; the author chose the log formats, detector
comparisons, evaluation framing, debugging priorities, and final claims, and verified
the final code and write-up.*

See [REFERENCES.md](REFERENCES.md) for the threat and event-source citations most
relevant to this project.

> **Publication status.** This project currently measures *engineering correctness*, not a
> real-data detection result. The focused, falsifiable research question and the locked,
> leakage-resistant evaluation protocol are defined in [PUBLICATION_PLAN.md](PUBLICATION_PLAN.md)
> (Phases 1-2). Phases 3-4 — measuring precision/recall, alert burden, and time-to-detection on
> real labeled data — require the LANL authentication corpus, which is distributed through a
> manual request form (see [LANL_ACQUISITION.md](LANL_ACQUISITION.md)). The claims in this paper
> are scoped to what the current evidence supports.

## Abstract

Brute forcing, password spraying, and the compromise that follows a successful guess
all leave traces in authentication logs — but rarely in a format you can compare
across machines. A Linux host writes SSH history as free text, a Windows domain
controller records Security events 4624/4625, and a SIEM hands back a tidy CSV that
has forgotten where it came from. This project is a small command-line tool that
folds all three into one event representation and then runs a set of detectors over
the result: failure counting per source and account, correlation of a successful
login with the failures that immediately preceded it, density of failures within a
short time window, and a volume-based flag for sources that behave unlike their
peers. A later pass added two detectors that look at *change* rather than counts —
an account that succeeds from one address and then from another inside a day —
and a direct `.evtx` parser so the Windows path no longer depends on someone else's
CSV export.

The value of this project was never supposed to be a new algorithm; the detectors
are all conventional. It is an implementation that is careful about the failure
modes that only show up on real, mixed-format data. That is where the actual work
went: a timestamp-ordering bug that silently corrupted the success-after-failure
correlation on any log spanning more than one calendar month, a test suite that
failed because it spawned the wrong Python interpreter, and an input-boundary
design where every new format is assumed to be slightly different from the samples.

**The research question this work is being pointed at** is deliberately narrow and
falsifiable (see [PUBLICATION_PLAN.md](PUBLICATION_PLAN.md) Phase 1): *when a
defender has only authentication events, how early can a simple, transparent
detector flag a credential-compromise campaign, and what is the analyst alert
burden at that operating point?* The current evidence — a synthetic, small test
corpus and a corrected multi-format ingestion path — supports the *engineering*
claims below but is **not yet evidence of real detection performance**.

## 1. Why authentication logs

Authentication logs are the highest-value, lowest-cost telemetry a defender has. A
failed logon is cheap to record and, in aggregate, tells a clear story: sustained
failures against one account from one address is a brute-force attempt; a success
that lands after such a run is a plausible compromise; a single address touching an
unusual number of distinct accounts is spraying. None of this requires payload
inspection or endpoint agents — just the login record itself.

The practical obstacle is heterogeneity. The three formats I wanted to read have
nothing in common beyond the underlying event:

- **Linux `auth.log`**: lines like `Failed password for invalid user admin from
  203.0.113.7`. No year in the timestamp, no structure beyond a regex.
- **Windows Security events**: structured 4624 (success) / 4625 (failure) events,
  but only when you export them; the export shape depends on who exported it.
- **SIEM/CSV**: some normalized export where the provenance has been stripped.

A hunting workflow that speaks one dialect forces the analyst to normalize by hand,
and that is the step that gets skipped under time pressure. The tool's position is
that normalization belongs in the tool, not the analyst.

## 2. What the tool does

The ingestion layer now also supports Los Alamos National Laboratory's de-identified
enterprise authentication schema. A separate streaming evaluator can compare the
7.2 GB authentication corpus with LANL's red-team ground truth without loading the
full file into memory. Because the complete corpus requires LANL's download form,
this revision verifies the schema and evaluator but does not claim a full-corpus
operational recall or false-positive rate.

### 2.1 Ingestion

Format is either declared or auto-detected. Linux logs are parsed with two regular
expressions, one for `Failed password` and one for `Accepted`. Windows CSV exports
are filtered to event IDs 4624/4625. The EVTX path reads the binary container with
`python-evtx` and converts each record's XML to the same schema; that conversion is
a pure function, tested in isolation, so the library's quirks never leak into the
detection logic. After parsing, `status` is lower-cased and a real datetime column
is derived from the raw timestamp string.

### 2.2 Detectors

**Brute force (count).** Failures grouped by `(source_ip, username)`; any pair at or
above a threshold (default 5) is reported.

**Success after failures.** For each `(source_ip, username)` pair, events are walked
in true chronological order with a running failure count that resets on success. A
success reached while the count is at or above threshold is a likely post-brute-force
compromise. This detector is the one most sensitive to ordering, which is why the
timestamp bug in §3.1 mattered.

**Burst (time-window).** The count detector treats five failures spread over two
days identically to five failures in a minute. This detector separates them: for
each source, it measures how many failures fall inside a trailing window (default
5 minutes) and reports the source at its densest moment. This is the detector that
actually distinguishes password-spraying *style* from a slow credential drip.

**Lateral movement.** An account that succeeds from one address and then, within 24
hours, succeeds from a different address is the classic shape of a replayed
credential. Only distinct consecutive successes are compared, so a user who
normally alternates between two known IPs is reported at most once.

**Unusual source-IP activity.** Per-source event totals and distinct-user counts are
compared against mean plus one population standard deviation. Sources beyond either
cutoff get a medium-severity finding. With fewer than two sources the detector
returns nothing, since a single source has no standard deviation to measure against.

Findings are de-duplicated, severity-ordered, and written as CSV, JSON, and two plots.

### 2.3 A correctness defect in timestamp ordering

The success-after-failures detector depends on walking events in true chronological
order. The original implementation sorted on the raw `timestamp` string. For ISO-8601
CSV timestamps that is safe, because lexical and chronological order coincide. For
Linux syslog timestamps it is not: they carry a month *name* and no year, so a string
sort orders `May 10` by the alphabetical order of the month abbreviation. Concretely,
December 1, February 1, and January 15 sort lexically as *December, February,
January* — the reverse of one and the transposition of the others. On any log
spanning a month boundary, the failure run preceding a success could therefore be
miscounted, silently producing false negatives or false positives. The bundled sample
data hid the bug because all its events fall within a single morning.

The fix parses timestamps once, at load time, into a datetime column, and all
ordering uses that column. Year-less syslog timestamps are assumed to fall in the
current year, which keeps ordering correct within one file; unparseable values
become `NaT` and sort last rather than raising. Recovering the true year across a
log-rotation boundary at a New Year remains an open limitation, deliberately left
alone.

## 3. Evaluation

The corpus is synthetic and small, so accuracy numbers against it would be
meaningless. The relevant results are behavioral: does the tool hold together on all
three formats, and do the new detectors change the story only where they should?

| Format | Events | Findings |
|--------|:------:|:--------:|
| Normalized CSV | 19 | 6 |
| Linux `auth.log` | 11 | 5 |
| Windows events | 10 | 3 |

(These counts include the two newer detectors, so the CSV sample that used to yield
4 findings now yields 6 — a burst and a lateral-movement finding on top of the
original brute-force and post-breach hits.)

Test coverage was rebuilt from two failing end-to-end smoke tests into a 26-test
suite. The old tests failed not on logic but because they spawned a bare `python`
subprocess that resolved to an interpreter without the project's dependencies — a
genuine portability defect that passes only where `python` on `PATH` happens to be
the right environment. The tests now spawn `sys.executable`. The unit suite covers
each detector on hand-built frames, including regression tests for the timestamp
bug (deliberately out-of-order month-name timestamps) and for the new detectors
(a dense burst vs. a slow drip; a new-source success inside vs. outside the window;
the EVTX record conversion).

## 4. Limitations

- The corpus is synthetic; no claim is made about detection rates on real traffic.
- No real-data detection result is reported. The LANL evaluator (`evaluate_lanl.py`) is schema-
  verified and streaming, but the full corpus is distributed through LANL's request form
  (see [LANL_ACQUISITION.md](LANL_ACQUISITION.md)), so Phases 3-4 of the publication plan remain
  to be run once the corpus is obtained.
- Syslog year inference assumes the current year and does not handle rotation
  across a New Year boundary.
- The lateral-movement detector compares consecutive successes only; it cannot see
  a first-time source that never appeared before in the window.
- The source-IP anomaly flag uses volume alone, with no enrichment or reputation.
- Ground truth for a real corpus is the red-team set only; intrusions not in the red-team set
  would be invisible to the label (affecting measured recall, not precision).

## 5. Future work

The most valuable next step is treating these detectors as a small ensemble rather
than independent flags — the burst, lateral, and success-after-failures detectors
all fire on related evidence and could be combined with explicit reasoning about
which alert the analyst should look at first. Enriching source addresses with
threat-intelligence reputation would corroborate the volume-based detector, and
handling EVTX timestamp quirks (such as the missing-year inference) would remove
the last real-world assumption.

## 6. Conclusion

The engineering value of this pass was less in the detectors, which are conventional,
than in making them trustworthy: finding a timestamp-ordering defect that a casual
read and the sample data both hide, fixing an environment-dependent test failure,
and leaving behind a test suite that pins the corrected behavior. A hunting tool
that is wrong only on inputs its own samples never reach is the most dangerous
kind, because it looks correct. The work here was mostly about closing that gap.
