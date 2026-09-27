from __future__ import annotations
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
ART=ROOT/'models'/'artifacts'/'ntro-world-bootstrap-v1'

def main()->int:
    metadata=json.loads((ART/'metadata.json').read_text(encoding='utf-8')); metrics=json.loads((ART/'metrics.json').read_text(encoding='utf-8')); cal=json.loads((ART/'calibration.json').read_text(encoding='utf-8'))
    lines=['# AegisNet-WM Temporal World Model — Model Card','',f"**Evidence status:** `{metrics['evidence_status']}`",'', '> These metrics are bootstrap integration evidence, not final real-world generalisation claims.','', '## Architecture','',f"- History: {metadata['history_steps']} × {metadata['window_seconds']} s",f"- Horizons: {metadata['horizons_seconds']} seconds",f"- Latent dimension: {metadata['latent_dim']}",f"- Input features: {len(metadata['features'])}",'- Learned free-running latent transition with future-state reconstruction loss','- Heads: future attack class, attack onset, infiltration probability, next victim','', '## Bootstrap evaluation','', '| Horizon | Accuracy | Macro-F1 | Brier | Benign FPR | Onset AUROC | Onset AUPRC | Infiltration AUROC | Victim accuracy | Abstain threshold |','|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for key,item in metrics['world_model'].items():
        lines.append(f"| +{int(key)*metadata['window_seconds']}s | {item['accuracy']:.3f} | {item['macro_f1']:.3f} | {item['brier_multiclass']:.3f} | {item['benign_false_positive_rate']:.3f} | {item.get('onset_auroc',0):.3f} | {item.get('onset_auprc',0):.3f} | {item.get('infiltration_auroc',0):.3f} | {item['victim_accuracy']:.3f} | {cal[key]['threshold']:.2f} |")
    lines += ['', '## Baselines','', 'The training artifact also records persistence, logistic-regression forecast, empirical Markov, and direct-GRU baselines on the identical bootstrap split.', '', '## Required before headline claims','', '- Train/evaluate on real temporal public data (CIC-IDS-2017 importer is implemented).','- Collect multiple independent clean EVE campaigns per class and progression.','- Report multi-seed confidence intervals and real warning lead time.','- Run packet-feature/full-state ablations after clean aligned PCAP collection.']
    out=ART/'MODEL_CARD.md'; out.write_text('\n'.join(lines)+'\n',encoding='utf-8'); print(out); return 0
if __name__=='__main__': raise SystemExit(main())
