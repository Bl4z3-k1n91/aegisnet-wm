# AegisNet-WM Temporal World Model — Model Card

**Evidence status:** `synthetic_transition_bootstrap`

> These metrics are bootstrap integration evidence, not final real-world generalisation claims.

## Architecture

- History: 6 × 10 s
- Horizons: [10, 30, 60] seconds
- Latent dimension: 64
- Input features: 29
- Learned free-running latent transition with future-state reconstruction loss
- Heads: future attack class, attack onset, infiltration probability, next victim

## Bootstrap evaluation

| Horizon | Accuracy | Macro-F1 | Brier | Benign FPR | Onset AUROC | Onset AUPRC | Infiltration AUROC | Victim accuracy | Abstain threshold |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| +10s | 0.889 | 0.822 | 0.124 | 0.000 | 1.000 | 0.000 | 1.000 | 0.942 | 0.00 |
| +30s | 0.720 | 0.662 | 0.317 | 0.000 | 1.000 | 0.000 | 0.966 | 0.864 | 0.40 |
| +60s | 0.798 | 0.759 | 0.224 | 0.000 | 0.997 | 0.000 | 0.966 | 0.873 | 0.35 |

## Baselines

The training artifact also records persistence, logistic-regression forecast, empirical Markov, and direct-GRU baselines on the identical bootstrap split.

## Required before headline claims

- Train/evaluate on real temporal public data (CIC-IDS-2017 importer is implemented).
- Collect multiple independent clean EVE campaigns per class and progression.
- Report multi-seed confidence intervals and real warning lead time.
- Run packet-feature/full-state ablations after clean aligned PCAP collection.
