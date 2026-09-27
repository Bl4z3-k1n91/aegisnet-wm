# EVE Forecasting Validation Protocol

This protocol is the local-domain evidence path for AegisNet-WM.  Public
datasets remain useful external evidence, but their thresholds are never
assumed to transfer into the EVE lab.

## Priority triage

### P0 — validity and authority boundary

1. Record exact EVE cyber-stage boundaries with
   `experiments/cyber_scenario_runner.py`.
2. Build 10-second states, 60-second histories and +10/+30/+60 labels with
   `models/world_model/lab_temporal_dataset.py`.
3. Train the EVE-local stacker with `eve_shadow_calibration.py`.
4. Keep every external/calibrated forecast `alert_authority=false`.  Passing a
   promotion gate only means the evidence is eligible for manual review.

### P1 — forecasting proof

1. Measure AUROC/AUPRC, recall, FPR, raw false-alert windows/hour and
   false-alert episodes/hour.
2. Measure warning lead only when the forecast is emitted **before** the exact
   attack-phase start.  Post-onset detections are excluded.
3. Run `benign-soak` scenarios to estimate operational false alarms under
   harmless mixed traffic.
4. Save the evidence with `tools/evidence_bundle.py`.

### P2 — stage progression and operator UX

1. Keep the binary future-attack forecast as the primary claim.
2. Train the separate transition-focused `train_next_stage.py` model instead
   of forcing the high-performing binary head to solve exact stage prediction.
3. Display the next-stage output and EVE-calibrated probabilities as shadow
   evidence in the terminal.

### P3 — ablation and reproducibility

The evidence bundle retains identical-split comparisons for persistence,
Markov, logistic forecast, direct GRU (no rollout), and the latent world model.
Do not use all-window persistence accuracy as a forecasting headline: long
steady states make persistence artificially strong.  Use transition-only and
pre-onset metrics for forecasting claims.

## Collection commands

```powershell
# Train split: benign -> recon -> initial-access pattern
$env:EVE_PASSWORD = Read-Host "EVE password"
D:\deep\python.exe .\experiments\cyber_scenario_runner.py recon-initial-access `
  --split train --baseline-seconds 60 --recon-seconds 60 `
  --attack-seconds 60 --recovery-seconds 60

# Independent test progression: benign -> recon -> bounded DDoS
D:\deep\python.exe .\experiments\cyber_scenario_runner.py recon-ddos `
  --split test --baseline-seconds 60 --recon-seconds 60 `
  --attack-seconds 60 --recovery-seconds 60

# Long harmless soak
D:\deep\python.exe .\experiments\cyber_scenario_runner.py benign-soak `
  --split test --soak-seconds 1800
```

Use multiple complete runs in each split.  Never split overlapping windows from
one run across train/validation/test.

## Build the local temporal release

```powershell
D:\deep\python.exe .\models\world_model\lab_temporal_dataset.py `
  --feature-mode flow `
  --output .\dataset\releases\eve-cyber-temporal-v1
```

The release now includes `run_id`, `scenario`, `sample_time`, `campaign_id`,
`source_campaign_id` and `next_stage` arrays in addition to the existing
world-model targets.  `campaign_id` is deliberately rewritten to the complete
run identity so overlapping windows from one run can never cross splits; the
original collection campaign is retained in `source_campaign_id`.

## Fit the EVE-local shadow stacker

```powershell
D:\deep\python.exe .\models\world_model\eve_shadow_calibration.py `
  --data-dir .\dataset\releases\eve-cyber-temporal-v1 `
  --output-dir .\models\artifacts\eve-shadow-calibration-v1 `
  --max-fpr 0.01 --min-recall 0.80 --max-false-alerts-per-hour 1
```

The output contains `metrics.json`, `thresholds.json` and `promotion.json`.
`promotion.json` can say `eligible=true`; it still says
`alert_authority=false` and does not alter the operator health state.

## Evaluate live forecasts against phase ground truth

```powershell
D:\deep\python.exe .\experiments\forecast_evaluator.py `
  --signal eve-calibrated
```

If the local calibrator has not been trained yet, evaluate the current world
model with `--signal world` or the raw public consensus with
`--signal shadow-mean`.

## Build the final evidence package

```powershell
D:\deep\python.exe .\tools\evidence_bundle.py --run-tests
```

The latest machine-readable and Markdown summaries are written to
`outputs/evidence/latest.json` and `outputs/evidence/latest.md`.
