#!/usr/bin/env python3
"""Package reproducible competition model weights without committing binaries to git."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
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


def git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def deterministic_info(name: str) -> zipfile.ZipInfo:
    """Return a stable ZIP entry independent of source mtimes/workstation."""

    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def add_bytes(bundle: zipfile.ZipFile, name: str, data: bytes) -> None:
    bundle.writestr(deterministic_info(name), data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--name", default="aegisnet-model-pack-v1")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{args.name}.zip"
    files: list[dict[str, object]] = []
    commit = git_commit()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for relative in DEFAULT_ARTIFACTS:
            directory = ROOT / relative
            if not directory.is_dir():
                raise RuntimeError(f"required model artifact is missing: {directory}")
            for path in sorted(directory.rglob("*")):
                if not path.is_file() or path.name.startswith("."):
                    continue
                arcname = path.relative_to(ROOT).as_posix()
                data = path.read_bytes()
                add_bytes(bundle, arcname, data)
                files.append({
                    "path": arcname,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })
        training = ROOT / "config" / "world_model_training.json"
        if training.exists():
            data = training.read_bytes()
            add_bytes(bundle, training.relative_to(ROOT).as_posix(), data)
            files.append({
                "path": training.relative_to(ROOT).as_posix(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        manifest = {
            "schema_version": 1,
            "purpose": "SIH/NTRO reproducible offline model weights",
            "source_commit": commit,
            "archive_policy": "deterministic ZIP_STORED entries with fixed timestamps and sorted paths",
            "artifacts": list(DEFAULT_ARTIFACTS),
            "files": files,
        }
        add_bytes(
            bundle,
            "MODEL-PACK-MANIFEST.json",
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
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
