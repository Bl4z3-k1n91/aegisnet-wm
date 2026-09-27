#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "intelligence"))
sys.path.insert(0, str(ROOT / "models"))
from artifact_integrity import verify_manifest  # noqa: E402
from audit_chain import verify as verify_audit  # noqa: E402
from production_guard import load_policy, telemetry_health, verify_file_sha256  # noqa: E402


def jload(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AegisNet production-readiness gates.")
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs" / "production-readiness.json")
    args = parser.parse_args()
    policy = load_policy()
    checks: dict[str, dict[str, Any]] = {}

    telemetry = telemetry_health(
        ROOT / "outputs" / "telemetry-status.json",
        heartbeat_max_age_seconds=float(policy["telemetry"]["heartbeat_max_age_seconds"]),
        max_poll_error_fraction=float(policy["telemetry"]["max_poll_error_fraction"]),
    )
    checks["telemetry_health"] = {"pass": bool(telemetry.get("healthy")), **telemetry}

    analysis = jload(ROOT / "outputs" / "analysis-status.json") or {}
    checks["analysis_service"] = {
        # NO_DATA is an intentional fail-closed inference state, not a process
        # or platform failure. Production health must remain green while the
        # decision plane explicitly reports that inference is unavailable.
        "pass": analysis.get("state") == "RUNNING",
        "inference_ready": analysis.get("mode") not in {"NO_DATA"},
        "state": analysis.get("state"),
        "mode": analysis.get("mode"),
        "operator_state": analysis.get("operator_state"),
    }

    artifact_paths = [
        ROOT / policy["current_detector_artifact"],
        ROOT / policy["world_model_artifact"],
        ROOT / policy["binary_detector_challenger"],
        ROOT / policy["stage_detector_challenger"],
        ROOT / "models" / "artifacts" / "genis-open-world-v1",
        ROOT / "models" / "artifacts" / "ctu13-open-world-v1",
        ROOT / "models" / "artifacts" / "cicids2017-open-world-v1",
        ROOT / "models" / "artifacts" / "eve-shadow-calibration-v1",
        ROOT / "models" / "artifacts" / "genis-next-stage-v1",
    ]
    integrity = [verify_manifest(path, require=True) for path in artifact_paths]
    checks["artifact_integrity"] = {
        "pass": all(item.get("valid") for item in integrity),
        "artifacts": integrity,
    }

    world_metadata = jload(ROOT / policy["world_model_artifact"] / "metadata.json") or {}
    allowed = set(policy.get("world_model_allowed_evidence") or [])
    checks["real_data_world_model"] = {
        "pass": world_metadata.get("evidence_status") in allowed,
        "release": world_metadata.get("model_release"),
        "evidence_status": world_metadata.get("evidence_status"),
    }

    promotion = jload(ROOT / "models" / "artifacts" / "eve-shadow-calibration-v1" / "promotion.json") or {}
    checks["forecast_promotion"] = {
        "pass": bool(promotion.get("eligible")),
        "eligible": bool(promotion.get("eligible")),
        "reason": promotion.get("reason"),
    }

    binary_metadata = jload(ROOT / policy["binary_detector_challenger"] / "metadata.json") or {}
    acceptance_path = ROOT / str(policy.get("authority_acceptance_report") or "outputs/authority-acceptance.json")
    binary_test = jload(acceptance_path) or {}
    expected_campaign = policy.get("authority_acceptance_campaign")
    acceptance_matches = (
        binary_test.get("artifact") == binary_metadata.get("model_release")
        and binary_test.get("campaign_id") == expected_campaign
    )
    checks["binary_authority_acceptance"] = {
        "pass": bool(binary_test.get("promotion_evidence_pass")) and acceptance_matches,
        "artifact": binary_metadata.get("model_release"),
        "authority_enabled": bool(policy.get("current_detector_authority_enabled", False)),
        "acceptance_report": str(acceptance_path),
        "campaign_matches": acceptance_matches,
        "acceptance": binary_test,
    }

    ood = jload(ROOT / policy["ood"]["profile"]) or {}
    ood_integrity = verify_file_sha256(
        ROOT / policy["ood"]["profile"],
        policy["ood"].get("profile_sha256"),
    )
    checks["ood_profile"] = {
        "pass": (
            int(ood.get("state_rows") or 0) >= int(policy["ood"]["minimum_profile_rows"])
            and bool(ood_integrity.get("valid"))
        ),
        "state_rows": int(ood.get("state_rows") or 0),
        "minimum_rows": int(policy["ood"]["minimum_profile_rows"]),
        "evidence_status": ood.get("evidence_status"),
        "integrity": ood_integrity,
    }

    try:
        connection = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
        quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
        connection.close()
        checks["database_integrity"] = {
            "pass": str(quick).lower() == "ok" and str(journal).lower() == "wal",
            "quick_check": quick,
            "journal_mode": journal,
        }
    except Exception as exc:
        checks["database_integrity"] = {"pass": False, "error": f"{type(exc).__name__}: {exc}"}

    audit = verify_audit(ROOT / "outputs" / "forecast-audit.jsonl")
    checks["forecast_audit_chain"] = {"pass": bool(audit.get("valid")), **audit}

    usage = shutil.disk_usage(ROOT)
    free_gb = usage.free / (1024 ** 3)
    checks["disk_capacity"] = {"pass": free_gb >= 5.0, "free_gb": free_gb, "minimum_free_gb": 5.0}

    git_dir = ROOT / ".git"
    checks["source_control"] = {
        "pass": git_dir.is_dir() and any(git_dir.iterdir()),
        "git_metadata_present": git_dir.is_dir() and any(git_dir.iterdir()) if git_dir.is_dir() else False,
    }
    try:
        git_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True)
        git_status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True)
        checks["source_control"].update({
            "pass": git_head.returncode == 0,
            "commit": git_head.stdout.strip() if git_head.returncode == 0 else None,
            "working_tree_clean": git_status.returncode == 0 and not bool(git_status.stdout.strip()),
        })
    except Exception as exc:
        checks["source_control"].update({"pass": False, "error": f"{type(exc).__name__}: {exc}"})

    prod_requirements = ROOT / "requirements-prod.txt"
    pinned_lines = []
    if prod_requirements.exists():
        pinned_lines = [
            line.strip() for line in prod_requirements.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    checks["dependency_pinning"] = {
        "pass": bool(pinned_lines) and all("==" in line for line in pinned_lines),
        "file": str(prod_requirements),
        "pinned_dependencies": len(pinned_lines),
    }

    backup_root = ROOT / "backups"
    backup_manifests = sorted(backup_root.glob("*/backup-manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True) if backup_root.exists() else []
    checks["rollback_backup"] = {
        "pass": bool(backup_manifests),
        "latest": str(backup_manifests[0]) if backup_manifests else None,
    }

    if args.run_tests:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-v"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        checks["regression_tests"] = {
            "pass": result.returncode == 0,
            "returncode": result.returncode,
            "tail": "\n".join((result.stdout + result.stderr).splitlines()[-12:]),
        }

    platform_names = {
        "telemetry_health", "analysis_service", "artifact_integrity", "real_data_world_model",
        "ood_profile", "database_integrity", "forecast_audit_chain", "disk_capacity",
        "dependency_pinning", "rollback_backup",
    }
    platform_ready = all(checks[name]["pass"] for name in platform_names)
    predictive_advisory_ready = (
        bool(checks["real_data_world_model"]["pass"])
        and bool(checks["ood_profile"]["pass"])
        and bool(checks["artifact_integrity"]["pass"])
    )
    authority_ready = bool(checks["binary_authority_acceptance"]["pass"])
    safe_shadow_deployment_ready = platform_ready and predictive_advisory_ready and bool(checks["source_control"]["pass"])
    release_ready = safe_shadow_deployment_ready and authority_ready
    if args.run_tests:
        release_ready = release_ready and bool(checks["regression_tests"]["pass"])
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform_ready": platform_ready,
        "predictive_advisory_ready": predictive_advisory_ready,
        "safe_shadow_deployment_ready": safe_shadow_deployment_ready,
        "production_advisory_release_ready": safe_shadow_deployment_ready,
        "automated_alert_authority_ready": authority_ready,
        "production_release_ready": release_ready,
        "checks": checks,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if release_ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
