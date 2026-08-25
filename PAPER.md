# Credential-Attack Detection across Authentication Logs: What a Tool for Three Log Formats Taught Me

**Farooq Syed** · M.S. in Computer and Information Security Systems, Eastern Illinois University · 2023

*Independent research portfolio, prepared as part of a PhD application in cybersecurity.
Developed with AI coding assistance; the author chose the log formats, detector
comparisons, evaluation framing, debugging priorities, and final claims, and verified
the final code and write-up.*

See [REFERENCES.md](REFERENCES.md) for the threat and event-source citations most
relevant to this project.

> **Publication status.** The full LANL experiment is complete. The online evaluator streamed
> a 314,683,765-event evaluation frame, used a day-15 temporal split, and scored 86 test-period
> red-team events without look-ahead. The result is negative: the three count/correlation
> detectors detected no red-team events, while the lateral-movement rule reached recall 0.372
> at precision 0.0001 and an unusable alert burden. Metrics are conditional on the documented
> 24-hour-context plus 5% background sample; the reported FPR is explicitly a key-day proxy,
> not a population false-positive rate.

## Abstract

Brute forcing, password spraying, and compromise following a successful guess
can leave traces in authentication logs, but the formats differ across systems.
A Linux host writes SSH history as free text, a Windows domain controller records
Security events 4624/4625, and a SIEM may provide a normalized CSV with reduced
source context. This project is a command-line tool that
folds all three into one event representation and then runs a set of detectors over
the result: failure counting per source and account, correlation of a successful
login with the failures that immediately preceded it, density of failures within a
short time window, and a volume-based flag for sources that behave unlike their
peers. A later pass added two detectors that look at *change* rather than counts —
an account that succeeds from one address and then from another inside a day —
and a direct `.evtx` parser so the Windows path does not depend on a separate CSV export.

The contribution is not a new detection algorithm; the detectors are conventional.
It is an implementation and evaluation focused on failure modes that arise in
mixed-format data. The engineering work included correcting a timestamp-ordering
bug that silently corrupted the success-after-failure
correlation on any log spanning more than one calendar month, a test suite that
failed because it spawned the wrong Python interpreter, and an input-boundary
design where every new format is assumed to be slightly different from the samples.

The real-data question is deliberately narrow and falsifiable: *when a defender has only
authentication events, how early can simple, transparent detectors flag a credential-
compromise campaign, and what alert burden do they create?* On the sampled LANL frame, the
answer is unfavorable. Simple count and correlation rules do not separate the test-period
red-team activity from benign background at usable operating points. This is evidence about
the locked protocol and sampled frame, not a claim about every credential detector or every
enterprise network.

## 1. Why authentication logs

Authentication logs are a widely available, comparatively low-cost telemetry source. A
failed logon is inexpensive to record and, in aggregate, can indicate a recognizable pattern: sustained
failures against one account from one address can indicate a brute-force attempt; a success
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

The ingestion layer also supports Los Alamos National Laboratory's de-identified enterprise
authentication schema. A memory-bounded evaluator processed the source corpus into a
314.7-million-event frame and streamed it chronologically against LANL's red-team ground
truth. The frame retains 24-hour context around all 749 red-team events and a deterministic
5% background sample, so alert burden and the key-day FPR proxy are conditional on that frame
rather than population-wide estimates.

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

### 3.1 Full LANL temporal evaluation

The primary evaluation splits at day 15. Test detectors process events online, and no
pre-split event can trigger a test alert. Ground-truth matching uses `(source user, source
computer)`, permits each of the 86 test red-team events to match at most once, treats
pre-attack alerts as false positives, and requires non-negative time to detection.

| Detector | Alerts/day | TP | FP | Precision | Recall | F1 | Median TTD |
|---|---:|---:|---:|---:|---:|---:|---:|
| Brute force (≥5 failures) | 253.8 | 0 | 4,061 | 0 | 0 | 0 | — |
| Burst (≥5 failures/5 min) | 66.7 | 0 | 1,067 | 0 | 0 | 0 | — |
| Success after failures | 13.1 | 0 | 209 | 0 | 0 | 0 | — |
| New source within 24 h | 19,356.5 | 32 | 309,672 | 0.0001 | 0.3721 | 0.0002 | 0 s |

The zero TTD for the lateral rule is degenerate: the sampled context contains alerts at the
same second as matched red-team events. It should not be interpreted as instant operational
detection. The negative key-day denominator is 1,905,540; false alerts divided by that value
form the reported FPR proxy, which is kept separate from analyst alerts per represented day.

### 3.2 Engineering regression evaluation

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

Test coverage was rebuilt from two failing end-to-end smoke tests into a 43-test
suite. The old tests failed not on logic but because they spawned a bare `python`
subprocess that resolved to an interpreter without the project's dependencies — a
genuine portability defect that passes only where `python` on `PATH` happens to be
the right environment. The tests now spawn `sys.executable`. The unit suite covers
each detector on hand-built frames, including regression tests for the timestamp
bug (deliberately out-of-order month-name timestamps) and for the new detectors
(a dense burst vs. a slow drip; a new-source success inside vs. outside the window;
the EVTX record conversion).

## 4. Limitations

- LANL is de-identified research telemetry with red-team ground truth, not a complete record
  of every malicious event in the enterprise.
- Metrics are conditional on the 24-hour-context plus deterministic 5% background sample;
  sampling weights would be required for population-wide alert-burden estimates.
- The FPR value is false alerts per negative `(user, source-computer, day)` window, a proxy
  rather than a conventional event-level population FPR.
- Syslog year inference assumes the current year and does not handle rotation
  across a New Year boundary.
- The lateral-movement detector compares consecutive successes only; it cannot see
  a first-time source that never appeared before in the window.
- The source-IP anomaly flag uses volume alone, with no enrichment or reputation.
- Ground truth for a real corpus is the red-team set only; intrusions not in the red-team set
  would be invisible to the label (affecting measured recall, not precision).

## 5. Future work

The most valuable next experiment is a pre-registered sensitivity analysis over failure
thresholds, burst windows, lateral horizons, and alert cooldowns, reporting campaign-level
recall and alerts per analyst-day rather than selecting the best test setting. A stronger
baseline should add graph- or sequence-aware scoring while retaining the same temporal split
and one-use matching rules. Sampling-weighted alert burden and per-campaign confidence
intervals are also needed before submission.

## 6. Conclusion

The completed LANL evaluation changes this project from an engineering demonstration into a
defensible negative result for the tested protocol. Under a locked temporal protocol, conventional authentication-log
rules either miss all test red-team events or create an unusable alert burden. The result does
not show that threat hunting is ineffective; it shows that these transparent rules are not a
sufficient detector on this sampled frame. The timestamp, split, matching, and TTD regression
tests make that unfavorable conclusion substantially more credible than an attractive result
obtained from a faulty evaluator.
