#!/usr/bin/env python3
"""Start, stop, and inspect the local AegisNet production stack."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(script: Path, action: str) -> int:
    result = subprocess.run([sys.executable, str(script), action], cwd=ROOT)
    return int(result.returncode)


def health() -> dict[str, object]:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8510/healthz", timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
            payload["http_status"] = response.status
            return payload
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"error": str(exc)}
        payload["http_status"] = exc.code
        return payload
    except Exception as exc:
        return {"healthy": False, "ready": False, "error": f"{type(exc).__name__}: {exc}"}


def start() -> int:
    telemetry = ROOT / "telemetry" / "manage_telemetry.py"
    analysis = ROOT / "models" / "manage_analysis.py"
    health_mgr = ROOT / "ops" / "manage_health.py"
    for script in (telemetry, analysis, health_mgr):
        code = run(script, "start")
        if code not in {0}:
            return code
    print(json.dumps(health(), indent=2))
    return 0


def stop() -> int:
    scripts = (
        ROOT / "ops" / "manage_health.py",
        ROOT / "models" / "manage_analysis.py",
        ROOT / "telemetry" / "manage_telemetry.py",
    )
    code = 0
    for script in scripts:
        code = max(code, run(script, "stop"))
    return code


def status() -> int:
    payload = health()
    print(json.dumps(payload, indent=2))
    return 0 if payload.get("ready") else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "status", "restart"))
    args = parser.parse_args()
    if args.action == "start": return start()
    if args.action == "stop": return stop()
    if args.action == "restart":
        stop()
        return start()
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
