#!/usr/bin/env python3
"""Fail-closed SIH 26153 / NTRO competition-compliance audit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def exists(path: str) -> bool:
    return (ROOT / path).exists()


def contains(path: str, patterns: list[str]) -> tuple[bool, list[str]]:
    target = ROOT / path
    if not target.exists():
        return False, patterns
    text = target.read_text(encoding="utf-8", errors="replace")
    missing = [pattern for pattern in patterns if re.search(pattern, text, flags=re.I | re.S) is None]
    return not missing, missing


def git_value(*args: str) -> str | None:
    result = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else None


def check(name: str, passed: bool, evidence: Any, requirement: str) -> dict[str, Any]:
    return {"name": name, "pass": bool(passed), "requirement": requirement, "evidence": evidence}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "outputs" / "competition")
    args = parser.parse_args()
    checks: list[dict[str, Any]] = []

    packet_files = ["features/packet_state.py", "features/pcap_to_features.py", "features/offline_inputs.py"]
    packet_ok = all(exists(path) for path in packet_files)
    packet_terms_ok, packet_missing = contains(
        "features/packet_state.py",
        [r"ttl_std", r"tcp_window", r"fragment", r"payload_p95", r"retransmission", r"packet_unique_dst_ports"],
    )
    checks.append(check(
        "flow_and_packet_features",
        packet_ok and packet_terms_ok,
        {"files": packet_files, "missing_terms": packet_missing},
        "both flow-level and packet-level traffic features",
    ))

    uploader_ok, uploader_missing = contains(
        "ui/pages/2_Offline_File_Analysis.py",
        [r"file_uploader", r"pcap", r"csv", r"plotly", r"MITRE", r"Why this forecast"],
    )
    checks.append(check(
        "offline_pcap_csv_demo",
        uploader_ok and exists("models/offline_inference.py"),
        {"page": "ui/pages/2_Offline_File_Analysis.py", "missing_terms": uploader_missing},
        "fully offline interface accepts PCAP/CSV and displays timeline/stages/explanations",
    ))

    world_dir = ROOT / "models" / "artifacts" / "genis-world-v1"
    world_required = ["world_model.pt", "metadata.json", "metrics.json", "scaler.npz", "calibration.json"]
    checks.append(check(
        "learned_world_model",
        all((world_dir / name).exists() for name in world_required),
        {"artifact": str(world_dir), "required_files": world_required},
        "learned temporal transition model with weights/configuration",
    ))

    explain_ok, explain_missing = contains(
        "models/world_model/inference.py",
        [r"autograd\.grad", r"attribution", r"top_features"],
    )
    checks.append(check(
        "per_prediction_explainability",
        explain_ok,
        {"implementation": "gradient x input attribution", "missing_terms": explain_missing},
        "attention/SHAP/feature-attribution equivalent explanation",
    ))

    benchmark = ROOT / "outputs" / "competition" / "benchmark.json"
    benchmark_payload = json.loads(benchmark.read_text(encoding="utf-8")) if benchmark.exists() else {}
    benchmark_rows = benchmark_payload.get("rows") or []
    benchmark_fields_ok = bool(benchmark_rows) and all(
        all(
            key in row
            for key in (
                "world_macro_f1",
                "logistic_macro_f1",
                "world_attack_auroc",
                "world_benign_fpr",
            )
        )
        for row in benchmark_rows
    )
    checks.append(check(
        "logistic_same_feature_benchmark",
        benchmark_fields_ok and "same" in str(benchmark_payload.get("same_feature_contract", "")).lower(),
        benchmark_rows,
        "world-model benchmark against logistic regression on same features",
    ))

    chain_ok, chain_missing = contains(
        "experiments/cyber_scenario_runner.py",
        [r"full-kill-chain", r"RECONNAISSANCE", r"INITIAL_ACCESS_PATTERN", r"LATERAL_MOVEMENT", r"C2_BEACON_PATTERN", r"EXFILTRATION_LIKE"],
    )
    checks.append(check(
        "attack_stage_coverage",
        chain_ok,
        {"scenario": "full-kill-chain", "missing_terms": chain_missing},
        "Recon -> Initial Access -> Lateral Movement -> C2 -> Exfiltration mapping",
    ))

    training_ok = all(exists(path) for path in [
        "models/world_model/train.py",
        "config/world_model_training.json",
        "tools/package_models.py",
    ])
    checks.append(check(
        "reproducible_training_and_weights",
        training_ok,
        {"training_script": "models/world_model/train.py", "config": "config/world_model_training.json", "packager": "tools/package_models.py"},
        "training scripts, model weights, reproducible training configuration",
    ))

    deliverables = {
        "readme": exists("README.md"),
        "architecture_source": exists("submission/architecture-2page.md"),
        "presentation_source": exists("submission/technical-presentation-5slides.md"),
        "demo_script": exists("submission/demo-video-script.md"),
        "license": exists("LICENSE"),
    }
    checks.append(check(
        "submission_deliverables",
        all(deliverables.values()),
        deliverables,
        "source link, README, <=2-page architecture, <=2-min demo, <=5-slide presentation",
    ))

    rendered_path = ROOT / "submission" / "rendered-artifacts.json"
    rendered = json.loads(rendered_path.read_text(encoding="utf-8")) if rendered_path.exists() else {}
    rendered_by_name = {
        str(item.get("name")): item
        for item in rendered.get("artifacts", [])
        if isinstance(item, dict)
    }
    architecture_pdf = rendered_by_name.get("AEGISNET_WM_Architecture_2Page.pdf", {})
    presentation = rendered_by_name.get("AEGISNET_WM_Technical_Presentation_5Slides.pptx", {})
    video = rendered_by_name.get("AEGISNET_WM_Demo_96s.mp4", {})
    rendered_limits_pass = (
        int(architecture_pdf.get("pages") or 999) <= 2
        and int(presentation.get("slides") or 999) <= 5
        and float(video.get("duration_seconds") or 999.0) <= 120.0
        and bool(architecture_pdf.get("sha256"))
        and bool(presentation.get("sha256"))
        and bool(video.get("sha256"))
    )
    checks.append(check(
        "rendered_submission_limits",
        rendered_limits_pass,
        {
            "architecture_pages": architecture_pdf.get("pages"),
            "presentation_slides": presentation.get("slides"),
            "demo_duration_seconds": video.get("duration_seconds"),
            "verification_manifest": "submission/rendered-artifacts.json",
        },
        "rendered architecture <=2 pages, presentation <=5 slides, demo <=120 seconds",
    ))

    remote = git_value("remote", "get-url", "origin")
    commit = git_value("rev-parse", "HEAD")
    checks.append(check(
        "source_repository",
        bool(remote and commit),
        {"origin": remote, "commit": commit},
        "source code link",
    ))

    all_pass = all(item["pass"] for item in checks)
    payload = {
        "schema_version": 1,
        "problem_statement_id": 26153,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "competition_compliant": all_pass,
        "checks": checks,
        "claim_guard": (
            "genis-world-v1 is the benchmarked learned flow-temporal model. PCAP packet features are "
            "processed and fused as bounded supporting evidence in offline competition inference; no packet-fusion "
            "benchmark is claimed until a labelled packet-level training corpus is validated."
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "compliance.json"
    md_path = args.output_dir / "compliance.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# SIH 26153 competition compliance",
        "",
        f"Overall: **{'PASS' if all_pass else 'FAIL'}**",
        "",
        "| Requirement | Status |",
        "|---|---|",
    ]
    for item in checks:
        lines.append(f"| {item['requirement']} | {'PASS' if item['pass'] else 'FAIL'} |")
    lines += ["", f"> {payload['claim_guard']}", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    return 0 if all_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
