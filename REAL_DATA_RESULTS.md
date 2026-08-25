# Threat Hunting — LANL Online Evaluation Results

**Date:** 2026-08-25 · Implements the locked protocol (PUBLICATION_PLAN Phases 2-4) as an
online, stateful evaluator over the sampled LANL auth eval frame.

## Summary

Real metrics on the **sampled eval frame** (24-hour context around all 749 red-team events +
a deterministic 5% (day,key) background sample; 314,683,765 events total). Temporal split at
day 15: test-period red-team events = **86**. Online detectors emit an alert at the **first
threshold crossing**; matching is keyed by (src_user, src_computer), no look-ahead, each
red-team event matched once, pre-attack alerts are false positives.

| Detector | alerts | TP | FP | precision | recall | F1 | median TTD | FPR-proxy |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| brute-force (≥5 failures) | 4,061 | 0 | 4,061 | 0.0000 | 0.0000 | 0.0000 | — | 0.0021 |
| burst (≥5 in 5-min window) | 1,067 | 0 | 1,067 | 0.0000 | 0.0000 | 0.0000 | — | 0.0006 |
| success-after-failure | 209 | 0 | 209 | 0.0000 | 0.0000 | 0.0000 | — | 0.0001 |
| lateral (new source in 24h) | 309,704 | 32 | 309,672 | 0.0001 | 0.3721 | 0.0002 | 0 s | 0.1625 |

Statistical baseline: per-source failure count in test vs train mean + 2σ (threshold 3,799
failures/source); 25 test sources exceed it (count-only diagnostic; not user-keyed matching).

## Reading

- The count/correlation detectors (brute-force, burst, success-after-failure) detect **none**
  of the 86 test-period red-team events (recall 0). Their alerts are all false positives.
- Lateral-movement detects 32/86 red-team events (recall 0.37) but at **catastrophic
  precision** (0.0001): 309,672 false positives. The alert burden is unusable for an analyst
  (≈309k alerts, FPR-proxy 0.16 per negative key-day).
- This is a **complete, honest negative result** on this frame: simple count/correlation
  detectors do not separate LANL red-team activity from benign background under the locked
  temporal protocol.

## Caveats (must be stated with any use)

- **Conditional on the sampled frame.** Alert-burden and FPR-proxy are NOT population-wide;
  they are conditional on the 24h-context + 5%-background sample and would need sampling
  weights to generalize.
- **FPR-proxy** = false alerts per negative (src_user, src_computer, day) window; it is a
  documented proxy, not a true population false-positive rate.
- TTD = 0 s for lateral because the 24h context window captures alerts within the same second
  as the red-team events; median TTD is degenerate at this sampling/context.
- The 24h context window is a documented consequence of the detector's temporal horizon.
- Only count/correlation detectors are evaluated; no ML scorer is used for the detection
  decision (the ML score is a per-source failure-count baseline for PR/ROC context).

## Reproduction

```bash
# 1. Compact the auth corpus (two-stage; ~40 min) -> data/lanl_auth_window.parquet
python scripts/compact_lanl_auth.py --auth E:/auth.txt --redteam <redteam>.gz \
    --margin-days 1.0 --output data/lanl_auth_window.parquet --benign-sample 0.02
# 2. Build the sampled eval frame -> data/lanl_eval_frame.parquet (~35 min)
python scripts/build_lanl_eval_frame.py --input data/lanl_auth_window.parquet \
    --redteam <redteam>.gz --context-hours 24 --keep-frac 0.05 \
    --output data/lanl_eval_frame.parquet
# 3. Sort the frame by time -> data/lanl_frame_sorted.parquet (~13 min)
# 4. Online evaluation -> results/lanl_online.json
python scripts/online_lanl_eval.py --input data/lanl_eval_frame.parquet \
    --redteam <redteam>.gz --split-day 15 --delay-minutes 30 \
    --failed-threshold 5 --window-minutes 5 --lateral-hours 24 \
    --sorted-frame data/lanl_frame_sorted.parquet --output results/lanl_online.json
```

All large intermediate files are gitignored (regenerable from the raw E: corpus). The small
evidence files (`.done`, `.manifest.json`) and this results JSON are committed.