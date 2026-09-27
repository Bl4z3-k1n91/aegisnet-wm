# AegisNet-WM Temporal Forecasting

AegisNet now has two independent ML layers:

1. **Present-state detector** — Logistic Regression + Random Forest on the current 10-second traffic state.
2. **Temporal world model** — 6 × 10-second history -> GRU latent state -> learned free-running latent transition -> +10/+30/+60-second forecasts.

The temporal model emits, per horizon:

- future attack class probability distribution;
- explicit attack-onset probability;
- infiltration probability;
- predicted next victim/site;
- topology path from the dominant current source;
- gradient-based temporal feature attribution;
- MITRE ATT&CK tactic/technique context;
- advisory operator playbook actions.

## Evidence status

The currently deployed artifact `ntro-world-bootstrap-v1` is marked **synthetic_transition_bootstrap**. It is trained from temporal progressions bootstrapped from the clean lab class prototypes. This proves the end-to-end forecasting architecture and live integration; it must not be presented as the final real-world benchmark.

The real-data paths are implemented:

```powershell
# Import CIC-IDS-2017-compatible CSVs with file/day-level split
D:\deep\python.exe .\models\world_model\public_dataset.py D:\data\CICIDS2017 `
  --output .\dataset\releases\cicids-temporal-v1

# Train exactly the same model on that real temporal release
D:\deep\python.exe .\models\world_model\train.py `
  --data-dir .\dataset\releases\cicids-temporal-v1 `
  --output-dir .\models\artifacts\cicids-world-v1
```

For future clean EVE campaigns, `lab_temporal_dataset.py` supports three state schemas:

```powershell
# 29 flow features
D:\deep\python.exe .\models\world_model\lab_temporal_dataset.py --feature-mode flow

# 29 flow + 20 packet features
D:\deep\python.exe .\models\world_model\lab_temporal_dataset.py --feature-mode flow-packet

# full 81-feature state, including network health
D:\deep\python.exe .\models\world_model\lab_temporal_dataset.py --feature-mode full
```

Do not use `full` for headline attack training until the campaign passes the convergence/contamination gates; otherwise routing health can leak into attack labels.

## Evaluation

`train.py` reports per horizon:

- accuracy / macro-F1;
- multiclass Brier score and NLL;
- benign false-positive rate;
- attack AUROC/AUPRC;
- onset AUROC/AUPRC;
- infiltration AUROC/AUPRC;
- victim accuracy;
- confidence-based abstention coverage and retained accuracy;
- warning lead time.

Baselines are evaluated on the identical split:

- persistence;
- logistic forecast;
- empirical Markov transition;
- direct GRU forecaster with no latent rollout.

Multi-seed evaluation:

```powershell
D:\deep\python.exe .\models\world_model\multi_seed.py --seeds 11,23,37 --epochs 14
```

The aggregated bootstrap result is written to:

`models/artifacts/ntro-world-multiseed-v1/aggregate.json`

## Live architecture

```text
EVE endpoints
   -> IOS NetFlow
   -> telemetry.db
   -> live_analysis_service.py
      -> present-state RF/LR ensemble
      -> completed 10-second temporal state history
      -> latent world model
      -> topology + ATT&CK + playbook enrichment
      -> forecast_predictions table
      -> hash-chained forecast audit
      -> Markdown incident brief
   -> terminal UI
```

The world-model history is quantized to completed 10-second bins. NetFlow arrival frequency therefore cannot accidentally become the temporal sequence length.

## Local EVE domain adaptation

The public GeNIS/CTU-13/CICIDS2017 models remain `SHADOW_ONLY`.  The local
domain-adaptation path is implemented in `eve_shadow_calibration.py`: it stacks
the public-model probabilities using run-disjoint EVE scenario data, chooses
thresholds under an explicit validation-FPR constraint, and reports raw false
alerts/hour.  Even when its promotion gates pass, the runtime keeps
`alert_authority=false`; promotion is a separate manual policy decision.

Exact local cyber-stage boundaries are recorded by
`experiments/cyber_scenario_runner.py`.  Live-vs-ground-truth evaluation is
handled by `experiments/forecast_evaluator.py`, which excludes post-onset rows
from warning-lead calculations.  See `docs/eve_forecasting_protocol.md`.

Exact next-stage prediction is also kept separate from binary attack-risk
forecasting. `train_next_stage.py` trains a transition-focused model and the
live console labels its output as shadow evidence.

## Audit and reports

Each forecast appends to `outputs/forecast-audit.jsonl` using a SHA-256 hash chain. Verify it with:

```powershell
D:\deep\python.exe .\tools\forecast_status.py
```

Forecast incident briefs are written under `outputs/reports/`.
