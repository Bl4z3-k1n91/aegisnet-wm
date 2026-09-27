# AegisNet-WM Real-Dataset Evidence Summary

## Deployment decision

- Local EVE present-state detector remains the only operator-facing alert authority.
- Public-dataset models run in SHADOW mode because calibration does not automatically transfer across domains.
- GeNIS is the primary real sequential forecasting benchmark because it provides whole multi-stage scenarios at 10-second cadence.
- CICIDS2017 is retained as a strict cross-day stress test; its Friday test includes attack families absent from Mon-Wed training.
- CTU-13 is retained as an independent botnet/C2-oriented binary-forecast dataset.
- UNSW-NB15 is not used for alert-threshold calibration in its current split because the validation day contains no attack positives.

## GeNIS 3-seed latent world model

| Horizon | Attack AUROC mean | Attack AUPRC mean | Exact-class accuracy mean | Exact-class macro-F1 mean | Benign FPR mean |
|---:|---:|---:|---:|---:|---:|
| +10s | 0.992 | 0.943 | 0.821 | 0.285 | 0.150 |
| +30s | 0.975 | 0.787 | 0.855 | 0.280 | 0.113 |
| +60s | 0.952 | 0.642 | 0.871 | 0.284 | 0.097 |

Median warning lead across seeds: **60 s**.

## GeNIS dedicated open-world attack forecaster

| Horizon | AUROC | AUPRC | Recall | FPR |
|---:|---:|---:|---:|---:|
| +10s | 0.995 | 0.979 | 0.984 | 0.043 |
| +30s | 0.990 | 0.939 | 0.949 | 0.042 |
| +60s | 0.993 | 0.914 | 0.964 | 0.069 |

## Interpretation

- The strongest defensible real-data claim is **future attack probability**, not exact next-stage classification.
- Exact future-stage macro-F1 remains weak because transition windows (especially reconnaissance/onset) are rare relative to long benign/steady-state periods.
- GeNIS native thresholds are not promoted to EVE alerts; a lab-domain sanity test showed threshold transfer can create false positives.
- The terminal therefore shows real-data forecasts as independent shadow evidence and keeps `NETWORK STABLE / ATTACK DETECTED` under the locally calibrated EVE detector.

## Live verification

- Analysis service loaded shadow models: `GENIS`, `CTU13`, `CICIDS2017`.
- Persisted forecast JSON reports `mode=SHADOW_ONLY` and `alert_authority=false`.
- Harmless BR1 -> DC ping produced no shadow consensus native alert votes at +10/+30/+60 s during the verification run.
- UI health endpoint returned HTTP 200 after deployment.
- Full regression suite: 52 tests passed.
