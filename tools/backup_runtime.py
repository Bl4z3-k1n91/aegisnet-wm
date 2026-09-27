#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an online-safe AegisNet runtime backup.")
    parser.add_argument("--database", type=Path, default=ROOT / "outputs" / "telemetry.db")
    parser.add_argument("--output-root", type=Path, default=ROOT / "backups")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = args.output_root / stamp
    target.mkdir(parents=True, exist_ok=False)
    db_target = target / "telemetry.db"
    source = sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True)
    destination = sqlite3.connect(db_target)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()
    for relative in (
        Path("config") / "production_policy.json",
        Path("outputs") / "analysis-status.json",
        Path("outputs") / "telemetry-status.json",
        Path("outputs") / "production-decision-state.json",
        Path("outputs") / "evidence" / "latest.json",
        Path("outputs") / "demo" / "latest.json",
    ):
        source_path = ROOT / relative
        if source_path.exists():
            destination_path = target / relative
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination_path)
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "database_source": str(args.database),
        "files": {
            path.relative_to(target).as_posix(): {
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
            for path in sorted(target.rglob("*"))
            if path.is_file()
        },
    }
    (target / "backup-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"backup": str(target), "files": len(manifest["files"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
