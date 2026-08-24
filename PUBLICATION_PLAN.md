# THLA Publication Plan — Phase 1 & 2 (frozen for review)

**Project:** `threat-hunting-log-analysis` · **Status:** Phase 1-2 frozen; Phases 3-4 blocked on
real-data access (LANL acquisition). This document is the review-facing spec; it is not a
claim of results.

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
- **Ground-truth→alert matching** is defined *before* seeing detector output. Two matching rules,
  decided a priori:
  - **Event-match:** an alert's `(source, user, destination)` equals a red-team triple, raised at
    any time ≥ the red-team event time (never earlier — no look-ahead).
  - **Delay window:** an alert that matches but is raised more than `T_det=30 min` after the
    red-team event is counted as a *late* detection, and its cohort is attributed to
    time-to-detection rather than recall.
- **Benign / false-positive frame:** all non-red-team alerts are false positives **unless** they
  can be attributed to a red-team campaign. Because the ground truth is campaign-level and
  severe-imbalance, false positives are reported per host per day (operational), not as a global
  accuracy number.

### 2.4 Temporal train/test split (and campaign holdout)

- **Primary split — temporal (day-gated).** Sort the 58 days chronologically. Use days 1–40 as
  **train**, days 41–58 as **test**. No event from the test days is used in training.
- **Campaign holdout (extra-rigorous).** Do NOT put all red-team campaigns in training. Hold out
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

### 2.6 Baselines (Phase 4 — fair comparison)

At minimum, compare the proposed detector against:
- **B1 — fixed-rule baseline:** a static count threshold on failures per (source, user)
  (e.g. ≥5, ≥10) with no training.
- **B2 — frequency/statistical baseline:** per-source / per-account failure rate relative to a
  train-learned normal profile (z-score or mean+stdev cutoff), thresholds chosen on a train
  validation split.
- **B3 — ML baseline (one):** a supervised classifier (e.g. LogisticRegression or RandomForest)
  on hand-labeled train windows — *if* a window-level label can be derived from the red-team
  ground truth without leakage. Document the label derivation explicitly.
- **B4 — proposed method:** THLA's detector ensemble (brute-force count, success-after-failure,
  burst, lateral, unusual-source).

All baselines share the same input representation, the same temporal/campaign split, and the
same alert-matching rule.

### 2.7 Threshold-selection procedure (validation only)

- Every threshold (`failed_threshold`, `window_minutes`, `lateral_window_hours`, and any ML
  decision threshold / contamination) is selected on a **train-validation split** (held-out
  subset of the train days/campaigns) by optimizing the target operating metric (e.g.
  precision at a target recall, or FP-per-host/day at a floor recall). The selected value is
  then applied **once** to the untouched test partition.
- Explicitly forbidden: choosing any threshold using test-partition labels. The chosen
  thresholds and their validation objective are recorded in `results/protocol_thresholds.json`.

### 2.8 Seeds, reproducibility, and commands

- Fixed seed `0` for any stochastic element (ML CV folds, sampling); document any randomness.
- Commands (run after LANL files are in place):
  ```
  python evaluate_lanl.py --auth <LANL>/auth.txt.gz --redteam <LANL>/redteam.txt.gz \
      --window-hours 24 --output results/lanl_external_validation.json
  ```
  Plus the metric runner (Phase 3 tooling — see below) for precision/recall/PR-AUC/ROC-AUC,
  FP-per-host-per-day, time-to-detection, coverage-by-campaign, and per-{user,host,day,campaign}
  confidence intervals.
- `requirements.txt` already pins deps; add a `requirements-lock.txt` freeze before the run.

---

## Phase 3-4 — metrics and baselines (to run once the corpus is in place)

Phase 1-2 above deliberately front-loads the protocol. Phase 3-4 need the LANL corpus and are
ready to run the moment it is obtained:

- **Phase 3 metrics:** precision, recall, PR-AUC, ROC-AUC (where a score exists),
  **false positives per host/day** and **alerts per analyst/day**, **time-to-detection**,
  **detection coverage by campaign**, a **stricter temporal/campaign holdout**, and
  **confidence intervals** across users/hosts/days/campaigns. Alert burden and time-to-detection
  are required, not optional.
- **Phase 4:** the B1–B4 baselines, plus sensitivity to `window_minutes`, `failed_threshold`,
  missing events, and class imbalance.

### Evaluation implementation status

The evaluator is **online and stateful** (`scripts/online_lanl_eval.py`): for each
(src_user, src_computer) key it keeps only the state each detector needs (failure/success
counts, first/last event time, last failure time, a bounded trailing-window failure deque, a
per-user recent-success trail, and per-detector "already alerted" flags + first-alert time).
Events are processed chronologically (the frame is time-sorted via SQLite), and an alert is
emitted the first time a detector's threshold is crossed. The alert time is therefore the
**first threshold crossing**, not the last failure, so time-to-detection is valid.

Correctness properties pinned by `tests/test_online_lanl_eval.py` (7 tests):
- train-period (pre-split) events never contribute to test detection;
- only **test-period** red-team events are in the recall denominator;
- red-team matching is keyed by **(src_user, src_computer)**, not source alone;
- each red-team event can be matched at most once (no reuse);
- pre-attack alerts (before the ground-truth event) are **false positives**;
- time-to-detection is **non-negative** (alert must occur at/after the red-team event).

**FPR and alert-burden are separate metrics.** `alerts_per_analyst_day` is the raw alert
burden. `fpr_proxy` is reported as false alerts per **negative (key, day)** window in the test
period (a documented proxy for FPR, because the negative denominator is key-day windows, not a
defined negative-event set). Both are **conditional on the sampled eval frame** — they are not
population-wide unless sampling weights are applied.

The 24-hour context window intentionally produces a large frame (a documented consequence of
the detector's temporal horizon); the online evaluator is the memory-safe way to run it.

---

## Honest limits the paper must state

- The dataset is a single enterprise (LANL) — no cross-organisation claim.
- Ground-truth completeness: red-team events are the positive class; real intrusions not in the
  red-team set are invisible to the label (this affects measured recall, not precision).
- The delay-window and campaign-holdout assumptions are stated, not hidden.
- No deployment / operational-readiness claim; this is a measurement on one labeled corpus.
