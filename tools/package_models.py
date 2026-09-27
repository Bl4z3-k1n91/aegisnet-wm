#!/usr/bin/env python3
"""Package reproducible competition model weights without committing binaries to git."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACTS = (
    "models/artifacts/genis-world-v1",
    "models/artifacts/genis-next-stage-v1",
    "models/artifacts/eve-shadow-calibration-v1",
    "models/artifacts/aegis-binary-v6-temporal-authority",
    "models/artifacts/genis-open-world-v1",
    "models/artifacts/ctu13-open-world-v1",
    "models/artifacts/cicids2017-open-world-v1",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--name", default="aegisnet-model-pack-v1")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{args.name}.zip"
    files: list[dict[str, object]] = []
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for relative in DEFAULT_ARTIFACTS:
            directory = ROOT / relative
            if not directory.is_dir():
                raise RuntimeError(f"required model artifact is missing: {directory}")
            for path in sorted(directory.rglob("*")):
                if not path.is_file() or path.name.startswith("."):
                    continue
                arcname = path.relative_to(ROOT).as_posix()
                bundle.write(path, arcname)
                files.append({
                    "path": arcname,
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                })
        training = ROOT / "config" / "world_model_training.json"
        if training.exists():
            bundle.write(training, training.relative_to(ROOT).as_posix())
            files.append({
                "path": training.relative_to(ROOT).as_posix(),
                "bytes": training.stat().st_size,
                "sha256": sha256(training),
            })
        manifest = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "purpose": "SIH/NTRO reproducible offline model weights",
            "artifacts": list(DEFAULT_ARTIFACTS),
            "files": files,
        }
        bundle.writestr("MODEL-PACK-MANIFEST.json", json.dumps(manifest, indent=2) + "\n")
    digest = sha256(archive)
    hash_file = archive.with_suffix(archive.suffix + ".sha256")
    hash_file.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    summary = {
        "archive": str(archive),
        "sha256": digest,
        "bytes": archive.stat().st_size,
        "files": len(files),
        "hash_file": str(hash_file),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
