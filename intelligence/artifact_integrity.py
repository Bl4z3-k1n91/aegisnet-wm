from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST_NAME = "artifact-manifest.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_files(directory: Path) -> list[Path]:
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    )


def build_manifest(directory: Path) -> dict[str, Any]:
    directory = Path(directory).resolve()
    files = artifact_files(directory)
    entries = {
        path.relative_to(directory).as_posix(): {
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in files
    }
    directory_digest = hashlib.sha256()
    for name, entry in entries.items():
        directory_digest.update(f"{name}:{entry['sha256']}:{entry['size']}\n".encode("utf-8"))
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artifact": directory.name,
        "file_count": len(entries),
        "directory_sha256": directory_digest.hexdigest(),
        "files": entries,
    }


def write_manifest(directory: Path) -> Path:
    directory = Path(directory)
    manifest = build_manifest(directory)
    target = directory / MANIFEST_NAME
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return target


def verify_manifest(directory: Path, *, require: bool = True) -> dict[str, Any]:
    directory = Path(directory).resolve()
    target = directory / MANIFEST_NAME
    if not target.exists():
        return {
            "valid": not require,
            "status": "MISSING",
            "artifact": directory.name,
            "errors": ["artifact-manifest.json is missing"] if require else [],
        }
    try:
        expected = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "valid": False,
            "status": "INVALID_MANIFEST",
            "artifact": directory.name,
            "errors": [f"{type(exc).__name__}: {exc}"],
        }
    actual = build_manifest(directory)
    errors: list[str] = []
    expected_files = expected.get("files") or {}
    actual_files = actual.get("files") or {}
    for name in sorted(set(expected_files) | set(actual_files)):
        if name not in expected_files:
            errors.append(f"unexpected file: {name}")
            continue
        if name not in actual_files:
            errors.append(f"missing file: {name}")
            continue
        if expected_files[name].get("sha256") != actual_files[name].get("sha256"):
            errors.append(f"hash mismatch: {name}")
        if int(expected_files[name].get("size", -1)) != int(actual_files[name].get("size", -2)):
            errors.append(f"size mismatch: {name}")
    if expected.get("directory_sha256") != actual.get("directory_sha256"):
        errors.append("directory digest mismatch")
    return {
        "valid": not errors,
        "status": "VALID" if not errors else "TAMPERED",
        "artifact": directory.name,
        "directory_sha256": actual.get("directory_sha256"),
        "file_count": actual.get("file_count"),
        "errors": errors,
    }
