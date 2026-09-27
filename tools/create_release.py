#!/usr/bin/env python3
"""Create a rollback-safe local AegisNet production release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "intelligence"))
from artifact_integrity import verify_manifest  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "git command failed")
    return result.stdout.strip()


def jload(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", default="aegisnet-prod-advisory-v1")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--output-root", type=Path, default=ROOT / "releases")
    args = parser.parse_args()

    status = run_git("status", "--porcelain")
    if status and not args.allow_dirty:
        raise RuntimeError("working tree is dirty; commit changes before creating a release")
    commit = run_git("rev-parse", "HEAD")
    branch = run_git("branch", "--show-current")
    policy_path = ROOT / "config" / "production_policy.json"
    policy = jload(policy_path)

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
    artifacts = [verify_manifest(path, require=True) for path in artifact_paths]
    if not all(item.get("valid") for item in artifacts):
        raise RuntimeError("one or more model artifacts failed integrity verification")

    readiness_path = ROOT / "outputs" / "production-readiness.json"
    if not readiness_path.exists():
        raise RuntimeError("production readiness report missing")
    readiness = jload(readiness_path)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    release_dir = args.output_root / f"{args.name}-{stamp}"
    release_dir.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema_version": 1,
        "release_name": args.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git": {"commit": commit, "branch": branch, "dirty": bool(status)},
        "policy": {
            "path": "config/production_policy.json",
            "sha256": sha256(policy_path),
            "current_detector_authority_enabled": bool(policy.get("current_detector_authority_enabled", False)),
        },
        "readiness": {
            "platform_ready": bool(readiness.get("platform_ready")),
            "predictive_advisory_ready": bool(readiness.get("predictive_advisory_ready")),
            "safe_shadow_deployment_ready": bool(readiness.get("safe_shadow_deployment_ready")),
            "automated_alert_authority_ready": bool(readiness.get("automated_alert_authority_ready")),
            "production_release_ready": bool(readiness.get("production_release_ready")),
        },
        "deployment_mode": "PRODUCTION_ADVISORY" if not policy.get("current_detector_authority_enabled", False) else "PRODUCTION_AUTHORITY",
        "artifacts": artifacts,
        "rollback": {
            "git_commit": commit,
            "policy_sha256": sha256(policy_path),
            "instruction": "checkout the recorded commit and restore the production policy/model artifact manifests from this release",
        },
    }
    target = release_dir / "release-manifest.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (release_dir / "production_policy.json").write_text(policy_path.read_text(encoding="utf-8"), encoding="utf-8")
    (release_dir / "production-readiness.json").write_text(readiness_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(json.dumps({"release": str(release_dir), "commit": commit, "deployment_mode": manifest["deployment_mode"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
