#!/usr/bin/env python3
"""Build the judge-facing same-feature world-model benchmark."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact",
        type=Path,
        default=ROOT / "models" / "artifacts" / "genis-world-v1",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs" / "competition",
    )
    args = parser.parse_args()
    meta = json.loads((args.artifact / "metadata.json").read_text(encoding="utf-8"))
    metrics = json.loads((args.artifact / "metrics.json").read_text(encoding="utf-8"))
    rows = []
    for step in meta["horizons_steps"]:
        key = str(step)
        seconds = step * int(meta["window_seconds"])
        world = metrics["world_model"][key]
        logistic = metrics["classical_baselines"]["logistic_forecast"][key]
        gru = metrics["direct_gru_baseline"][key]
        rows.append(
            {
                "horizon_seconds": seconds,
                "world_accuracy": world["accuracy"],
                "world_macro_f1": world["macro_f1"],
                "world_attack_auroc": world["attack_auroc"],
                "world_attack_auprc": world["attack_auprc"],
                "world_attack_recall_at_0_5": world["attack_recall_at_0_5"],
                "world_benign_fpr": world["benign_false_positive_rate"],
                "logistic_accuracy": logistic["accuracy"],
                "logistic_macro_f1": logistic["macro_f1"],
                "direct_gru_accuracy": gru["accuracy"],
                "direct_gru_macro_f1": gru["macro_f1"],
                "macro_f1_gain_vs_logistic": world["macro_f1"] - logistic["macro_f1"],
            }
        )
    payload = {
        "artifact": meta["model_release"],
        "evidence_status": meta["evidence_status"],
        "data_release": meta["data_release"],
        "feature_count": len(meta["features"]),
        "same_feature_contract": (
            "world model and logistic baseline are trained/evaluated on the same final state feature vector; "
            "logistic receives only the current state while the world model receives six sequential states"
        ),
        "split_contract": "scenario-disjoint train/validation/test split from the artifact data release",
        "rows": rows,
        "warning": (
            "Persistence/Markov accuracy is inflated by long steady-state sequences and is not used as the "
            "headline forecasting comparison."
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "benchmark.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "benchmark.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# AEGISNET-WM benchmark",
        "",
        payload["same_feature_contract"],
        "",
        "| Horizon | World macro-F1 | Logistic macro-F1 | Gain | Attack AUROC | Attack AUPRC |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| +{row['horizon_seconds']}s | {row['world_macro_f1']:.3f} | "
            f"{row['logistic_macro_f1']:.3f} | {row['macro_f1_gain_vs_logistic']:+.3f} | "
            f"{row['world_attack_auroc']:.3f} | {row['world_attack_auprc']:.3f} |"
        )
    lines += [
        "",
        (
            "The logistic baseline uses the same feature representation but no temporal history. "
            "The world model consumes six consecutive 10-second states and rolls a learned latent transition forward."
        ),
    ]
    (args.output_dir / "benchmark.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
