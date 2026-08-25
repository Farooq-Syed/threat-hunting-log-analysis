# THLA Publication Protocol and Completed LANL Evaluation

**Project:** `threat-hunting-log-analysis` · **Status:** protocol implemented and the full
314,683,765-event online evaluation completed. Real metrics are in
`results/lanl_online.json` and `REAL_DATA_RESULTS.md`. Unrun sensitivity and stronger-baseline
experiments remain future work and are not presented as completed evidence.

---

## Phase 1 — Research question (narrow, falsifiable)

> **R1.** When a defender has only authentication events (no payload, no endpoint agent), how
> early can a *simple*, transparent detector flag a credential-compromise campaign — and what
> is the analyst alert burden (false positives per host/day) at that operating point?

We deliberately do **not** ask "how well does this threat-hunting tool work?" That framing is
not falsifiable. Instead the question has two measurable halves:
1. **Detection coverage / time-to-detection** on real attack campaigns, and
2. **Alert burden** — the cost of the alerts an analyst must triage.

**Hypothesis.** Simple count- and correlation-based detectors on authentication events can
flag compromise campaigns early (low time-to-detection) but at a high false-positive-per-host
cost; the *burst* and *lateral* detectors trade coverage for precision, and only an explicit
operating point (validation-selected threshold) keeps alert burden sustainable.

**Secondary questions.**
- **R2.** Does the burst (time-window) detector separate fast brute-force/spraying from a slow
  credential *drip* better than a pure count detector?
- **R3.** Does a change-based detector (success from a new source inside a window) catch
  campaigns the count-based detectors miss, and at what cost?

**What we are NOT claiming:** no new algorithm, no generic "threat-hunting tool," no
deployment-level detection-rate claim. The contribution is a *measurement*: coverage,
time-to-detection, and alert burden on real labeled authentication data under a
leakage-resistant split.

---

## Phase 2 — Locked evaluation protocol

This protocol is fixed *before* running any experiment. It is designed so that no event from
the same campaign or time period can appear in both train and test.

### 2.1 Dataset and access conditions

- **Primary:** LANL Comprehensive, Multi-Source Cyber-Security Events (a.k.a. LANL cyber1) —
  58 days of de-identified enterprise auth + process + DNS + netflow data, with a **severely
  imbalanced, well-defined red-team ground-truth** set (the positive class). ~12 GB compressed.
- **Access:** distributed through the LANL data-request form (see `LANL_ACQUISITION.md`). The
  form requires a human request and approval; this is a **manual step a reviewer/the author must
  complete**. The evaluator (`evaluate_lanl.py`) is streaming and does not require loading the
  full 7.2 GB auth file into memory.
- **File set used:** `auth.txt` (or `.gz`) + `redteam.txt` (or `.gz`). The red-team file is the
  ground-truth label source. Record SHA-256 of the exact files used; a manifest is written by
  `evaluate_lanl.py`.
- **License/terms:** LANL's data-use terms; de-identified data for research; cite the dataset
  (DOI 10.17021/1179829). No redistribution.

### 2.2 Event types and preprocessing

- Event type: **authentication events** (LANL `auth.txt`), columns (index, time, user, source
  computer, destination computer, auth type, logon type, auth orientation, outcome). The tool
  maps these to a normalized schema: `timestamp` (epoch→datetime), `username`, `source_ip`
  (mapped from source computer id), `status` (from outcome), `auth_type`, `logon_type`.
- Preprocessing rules:
  - `status ∈ {success, failure}` from the LANL `outcome` field (inclusive of the de-identified
    success/failure encoding; the tool's `parse_lanl_auth` already normalizes this).
  - Drop events with missing `time`/`user`. Keep the domain-controller (DC) auth events as the
    primary signal (they are the highest-coverage authentication source).
  - No enrichment, no threat-intel reputation, no IP geolocation — the experiment is
    deliberately restricted to what auth events carry.
- **No synthetic data** is used for the headline result. Synthetic logs remain a development /
  unit-test artifact only and are explicitly not a benchmark.

### 2.3 Threat / benign labeling method

- **Positive class (threat):** exactly the **red-team events** in `redteam.txt`. Each red-team
  record is a 4-tuple `(time, user, source_computer, destination_computer)`; any detector alert
  that covers the same `(user, source, destination)` campaign within a defined **acceptable
  delay window** counts as a detection of that ground-truth event.
- **Ground-truth→alert matching** was fixed before scoring. An alert matches the next unused
  red-team event for the same `(src_user, src_computer)` key when its timestamp is from the
  ground-truth time through 30 minutes afterward. Pre-event alerts never match, and each
  red-team event can be used once per detector.
- **Benign / false-positive frame:** every unmatched alert is a false positive. False alerts
  are reported both as alerts per represented test day and per negative
  `(src_user, src_computer, day)` window. The latter is explicitly an FPR proxy, not a
  population event-level false-positive rate.

### 2.4 Temporal train/test split (and campaign holdout)

- **Primary split — temporal (day-gated).** Sort chronologically and split at day 15, the
  realized locked operating point used by the evaluator. Events before day 15 are train-side;
  events at or after day 15 are test-side. No train event can trigger a test alert.
- **Campaign holdout (planned, not completed).** A future extension should hold out
  entire red-team *campaigns* (by the campaign/user-group implied by the red-team records) from
  training so the test measures **unseen-campaign** generalization, not re-detection of a known
  campaign. If campaign identity is not cleanly separable, use the temporal split as the primary
  and state that campaign identity is an open limitation.
- **Never random-row-split.** Random splits would place events from the same campaign or time
  period in both train and test, inflating apparent performance. This is the primary
  leakage guard.

### 2.5 Analyzer units and ground-truth scope

- The tools that need training (baseline "normal" profiles, thresholds) are fit on the **train
  partition only**. Any baseline statistic (mean/stdev of failures per source, per-hour normal
  rate) is computed on train and applied frozen to test.
- **Ground-truth in scope:** the red-team events that fall in the test days/campaigns. Red-team
  events in the train partition are used only to validate the matching procedure, not to detect.

### 2.6 Comparator status

The completed run reports four transparent detector outputs individually and a count-based
statistical diagnostic. The comparator plan is:
- **B1 — fixed-rule baseline:** a static count threshold on failures per (source, user)
  (e.g. ≥5, ≥10) with no training.
- **B2 — frequency/statistical diagnostic (completed):** per-source failure count relative to
  the train mean plus two standard deviations. It is not user-keyed and therefore is reported
  as context rather than a directly matched detection baseline.
- **B3 — ML baseline (planned):** a supervised classifier (e.g. LogisticRegression or RandomForest)
  on hand-labeled train windows — *if* a window-level label can be derived from the red-team
  ground truth without leakage. Document the label derivation explicitly.
- **B4 — transparent detector set (completed individually):** brute-force count,
  success-after-failure, burst, and lateral movement. No learned ensemble result is claimed.

Any future comparator must share the same sampled frame, realized temporal split, and
alert-matching rule. A future campaign-holdout comparison must likewise use one common,
predeclared campaign partition.

### 2.7 Threshold procedure

- The completed headline run uses fixed, documented thresholds chosen before scoring:
  `failed_threshold=5`, `window_minutes=5`, and `lateral_window_hours=24`. They were not tuned
  on test labels. Sensitivity across these values remains a required follow-up experiment.
- Explicitly forbidden: choosing any threshold using test-partition labels. The realized
  thresholds are recorded in the metadata of `results/lanl_online.json`.

### 2.8 Seeds, reproducibility, and commands

- Fixed seed `0` for any stochastic element (ML CV folds, sampling); document any randomness.
- Completed evaluation command (after building the sampled frame as documented in
  `REAL_DATA_RESULTS.md`):
  ```
  python scripts/online_lanl_eval.py --input data/lanl_eval_frame.parquet \
      --redteam <LANL>/redteam.txt.gz --split-day 15 --delay-minutes 30 \
      --failed-threshold 5 --window-minutes 5 --lateral-hours 24 \
      --output results/lanl_online.json
  ```
- The exact compaction and frame-building commands are recorded in `REAL_DATA_RESULTS.md`.

---

## Phase 3-4 — completed headline metrics and remaining extensions

The headline online run is complete. It reports precision, recall, F1, alert burden, the
key-day FPR proxy, and TTD for four transparent detectors. The following items remain
extensions rather than completed evidence:

- **Completed:** precision, recall, F1, alerts per represented test day, key-day FPR proxy, and
  time-to-detection for the four transparent detectors under the day-15 split.
- **Remaining:** detection coverage by campaign, uncertainty across stable campaign/day units,
  a campaign holdout, a directly matchable sequence/graph or ML baseline, sampling-weighted
  burden, and pre-registered sensitivity to `window_minutes`, `failed_threshold`, lateral
  horizon, missing events, and background sampling rate.

### Evaluation implementation status

The evaluator is **online and stateful** (`scripts/online_lanl_eval.py`): for each
(src_user, src_computer) key it keeps only the state each detector needs (failure/success
counts, a bounded trailing-window failure deque, and per-detector "already alerted" flags).
For lateral movement, an ordered map retains only each user's latest timestamp per active
source and expires stale sources; it does not retain every successful event. Events are processed
chronologically from a Parquet frame whose global time order is verified in a streaming pass,
and an alert is
emitted the first time a detector's threshold is crossed. The alert time is therefore the
**first threshold crossing**, not the last failure, so time-to-detection is valid.

Correctness properties pinned by `tests/test_online_lanl_eval.py` (12 tests):
- train-period (pre-split) events never contribute to test detection;
- only **test-period** red-team events are in the recall denominator;
- red-team matching is keyed by **(src_user, src_computer)**, not source alone;
- each red-team event can be matched at most once **within each detector**, while detectors are
  evaluated independently and may detect the same event;
- pre-attack alerts (before the ground-truth event) are **false positives**;
- time-to-detection is **non-negative** (alert must occur at/after the red-team event);
- the Parquet input is actually chronological, chronological inputs are reused without a copy,
  and outcome labels are normalized before detection.

**FPR and alert-burden are separate metrics.** `alerts_per_analyst_day` is the raw alert
burden divided by the number of represented test days. `fpr_proxy` is reported as distinct
false-alert **(key, day)** windows divided by all negative **(key, day)** windows in the test
period (a documented proxy for FPR, because the negative denominator is key-day windows, not a
defined negative-event set). Both are **conditional on the sampled eval frame** — they are not
population-wide unless sampling weights are applied.

The 24-hour context window intentionally produces a 314,683,765-row frame (a documented
consequence of the detector's temporal horizon). The locked frame was verified across all
314,683,765 timestamps as globally monotonic, so the evaluator streams it directly with bounded
per-key detector state—no SQLite index or duplicate 2 GB sorted file is required. For a future
unsorted input, the script can create and reuse an Arrow-sorted artifact when memory permits.

---

## Honest limits the paper must state

- The dataset is a single enterprise (LANL) — no cross-organisation claim.
- Ground-truth completeness: red-team events are the positive class; real intrusions not in the
  red-team set are invisible to the label (this affects measured recall, not precision).
- The delay-window and campaign-holdout assumptions are stated, not hidden.
- No deployment / operational-readiness claim; this is a measurement on one labeled corpus.
