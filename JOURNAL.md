# Dev journal — threat hunting log analysis

Notes to myself while cleaning this project up. Not polished. Mostly here so that
future-me remembers why things are the way they are.

## Where I started

The tool already worked. You point it at auth logs — a normalized CSV, a Linux
`auth.log`, or a Windows Security event export — and it spits out findings:
brute force by IP/user, a successful login that lands right after a pile of
failures, and source IPs that are noisier than the rest. There's a CSV report, a
JSON summary, and two plots. Honestly it was in decent shape. My goal this pass
wasn't to add features, it was to make sure it's actually correct and that the
tests prove it.

First thing I did was just run it on all three sample formats and write the
numbers down so I'd notice if I broke something:

- CSV sample: 19 events, 4 findings
- Linux auth: 11 events, 3 findings
- Windows events: 10 events, 2 findings

Then I ran the existing tests. Both failed. That was a surprise because the tool
clearly runs fine by hand.

## The test failure that wasn't a code bug (at first glance)

The traceback said `ModuleNotFoundError: No module named 'matplotlib'`, which made
no sense — I'd just watched matplotlib build its font cache when I ran the tool a
minute earlier. Took me a second to see it. The smoke test shells out with a bare
`"python"`:

```python
subprocess.run(["python", "log_hunter.py", ...])
```

On this machine `python` on PATH resolves to a *different* interpreter than the one
running pytest, and that other one doesn't have the project's deps. So the test was
launching the wrong Python. Classic. The fix is boring but correct — use
`sys.executable` so the subprocess is guaranteed to be the same interpreter that's
running the test:

```python
subprocess.run([sys.executable, "log_hunter.py", ...])
```

I like this one because it's the kind of bug that only shows up on someone else's
box (or in CI), never on the machine where it was written. Worth fixing before it
bites a reviewer.

## The real bug: timestamps were being sorted as strings

This is the one I'm actually a little proud of catching. The success-after-failures
detector groups events by (ip, user) and walks them in time order, counting a run
of failures until it sees a success. The ordering came from:

```python
group = group.sort_values("timestamp")
```

But `timestamp` is a **string**. For the ISO CSV timestamps that's fine, they sort
lexically the same as chronologically. For Linux syslog lines it is not fine at all,
because those look like `May 10 08:00:01` — month *name*, no year. Sorting those as
text sorts the month names alphabetically. I proved it to myself in the REPL:

```
input:   Dec 01, Feb 01, Jan 15
string sort:   Dec 01, Feb 01, Jan 15   <- wrong
chronological: Jan 15, Feb 01, Dec 01
```

So on any Linux log spanning more than one month, the failure/success run could be
counted in the wrong order and the correlation would be garbage. On the bundled
sample it happens to be within one morning so nothing looked wrong — which is
exactly why it survived this long.

Fix was to parse timestamps into a real datetime column (`event_time`) once, at load
time, and sort on that instead. `pd.to_datetime(..., errors="coerce")` handles the
ISO and Windows timestamps directly; the year-less syslog ones get assumed to the
current year, which keeps ordering correct within a single log. Anything genuinely
unparseable becomes `NaT` and sorts last instead of throwing.

I did NOT try to be clever about recovering the true year for syslog lines. That's a
real problem (log rotation across a new year) but it's out of scope for a cleanup
pass and I don't want to pretend I solved it.

## Small hardening while I was in there

- **Windows EventID parsing.** It was doing `int(row["EventID"])` straight up. One
  blank/merged row and the whole run dies. Wrapped it in a helper that returns `-1`
  for junk so those rows just get skipped by the `{4624, 4625}` check.
- **The `.get(col, fallback)` trap.** `row.get("TargetUserName", row.get("AccountName"))`
  looks right but if `TargetUserName` exists and is NaN, `.get` returns the NaN, it
  never reaches the fallback. Replaced with a small `_first_present` helper that
  treats NaN/empty as "not there."
- **Single-IP edge case.** The unusual-IP detector uses mean + std as a cutoff. With
  one IP the std is 0 and the cutoff is just the value, so it can never flag
  anything, but the math still ran. Now it bails early when there are fewer than 2
  IPs — clearer intent, no divide-by-nothing weirdness.
- **Matplotlib backend.** Forced `Agg` before importing pyplot so it never tries to
  open a window on a headless box.

## Tests

Rewrote the smoke tests to use `sys.executable` and added a third one for the Windows
format (it only covered CSV and Linux before). Then I added a real unit-test file
(`test_detection.py`) that imports the detector functions and feeds them tiny
hand-built frames. The one I care about most is the chronology test: it hands the
success-after-failures detector three rows with month-name timestamps deliberately
out of order, and asserts the count is right. That test would have failed against the
old string-sort code, which is the whole point — it pins the bug so it can't quietly
come back.

Final state: 17 tests, all green (was 2, both red). Re-ran the tool on all three
formats afterward and the finding counts matched what I wrote down at the start
(4 / 3 / 2), so the fixes didn't change behavior on the samples — they just made the
behavior correct on inputs the samples don't cover.

## What I'd do next if I come back

- Actually handle the syslog year-boundary problem instead of assuming current year.
- Time-window burst detection (N failures in M seconds) — right now it's a raw count,
  so a slow drip over a week looks the same as a burst in 30 seconds.
- Enrich source IPs with geo / threat intel so "unusual" has more to lean on than
  volume.
