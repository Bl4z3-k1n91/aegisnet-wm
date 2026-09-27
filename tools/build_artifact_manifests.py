#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "intelligence"))
from artifact_integrity import write_manifest, verify_manifest  # noqa: E402


DEFAULTS = [
    ROOT / "models" / "artifacts" / "ntro-clean-traffic-v1",
    ROOT / "models" / "artifacts" / "genis-world-v1",
    ROOT / "models" / "artifacts" / "genis-open-world-v1",
    ROOT / "models" / "artifacts" / "ctu13-open-world-v1",
    ROOT / "models" / "artifacts" / "cicids2017-open-world-v1",
    ROOT / "models" / "artifacts" / "eve-shadow-calibration-v1",
    ROOT / "models" / "artifacts" / "genis-next-stage-v1",
    ROOT / "models" / "artifacts" / "aegis-binary-v1-challenger",
    ROOT / "models" / "artifacts" / "aegis-current-v2-challenger",
    ROOT / "models" / "artifacts" / "aegis-world-v2-challenger",
    ROOT / "models" / "artifacts" / "aegis-binary-v3-challenger",
    ROOT / "models" / "artifacts" / "aegis-current-v3-stage",
    ROOT / "models" / "artifacts" / "aegis-binary-v2-challenger",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create SHA-256 manifests for deployed model artifacts.")
    parser.add_argument("paths", nargs="*", type=Path)
    args = parser.parse_args()
    results = []
    for directory in (args.paths or DEFAULTS):
        if not directory.exists():
            results.append({"artifact": str(directory), "status": "MISSING"})
            continue
        path = write_manifest(directory)
        verification = verify_manifest(directory, require=True)
        results.append({"artifact": str(directory), "manifest": str(path), **verification})
    print(json.dumps(results, indent=2))
    return 0 if all(item.get("valid", item.get("status") == "MISSING") for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
