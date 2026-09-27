#!/usr/bin/env python3
"""Local production health/readiness/metrics endpoint for AegisNet-WM."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "models"))
from production_guard import load_policy, telemetry_health  # noqa: E402


def jload(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def snapshot() -> dict[str, Any]:
    policy = load_policy()
    telemetry = telemetry_health(
        ROOT / "outputs" / "telemetry-status.json",
        heartbeat_max_age_seconds=float(policy["telemetry"]["heartbeat_max_age_seconds"]),
        max_poll_error_fraction=float(policy["telemetry"]["max_poll_error_fraction"]),
    )
    analysis = jload(ROOT / "outputs" / "analysis-status.json")
    analysis_running = analysis.get("state") == "RUNNING"
    advisory_guard = ((analysis.get("forecast") or {}).get("production_guard") or {})
    db_ok = False
    db_detail = "missing"
    db_path = ROOT / "outputs" / "telemetry.db"
    if db_path.exists():
        try:
            connection = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=2)
            try:
                db_detail = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                db_ok = db_detail.lower() == "ok"
            finally:
                connection.close()
        except Exception as exc:
            db_detail = f"{type(exc).__name__}: {exc}"
    ready = bool(telemetry.get("healthy")) and analysis_running and db_ok
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "healthy": bool(analysis_running and db_ok),
        "ready": ready,
        "telemetry": telemetry,
        "analysis": {
            "state": analysis.get("state"),
            "mode": analysis.get("mode"),
            "pid": analysis.get("pid"),
            "last_inference_at": analysis.get("last_inference_at"),
            "operator_state": analysis.get("operator_state"),
            "world_model": analysis.get("world_model"),
            "eve_shadow_calibration": analysis.get("eve_shadow_calibration"),
        },
        "database": {"healthy": db_ok, "quick_check": db_detail},
        "advisory_gate": {
            "status": advisory_guard.get("status"),
            "eligible": advisory_guard.get("advisory_eligible"),
            "reasons": advisory_guard.get("reasons") or [],
        },
    }


def prometheus(payload: dict[str, Any]) -> str:
    telemetry = payload.get("telemetry") or {}
    analysis = payload.get("analysis") or {}
    advisory = payload.get("advisory_gate") or {}
    values = {
        "aegisnet_health": int(bool(payload.get("healthy"))),
        "aegisnet_ready": int(bool(payload.get("ready"))),
        "aegisnet_telemetry_healthy": int(bool(telemetry.get("healthy"))),
        "aegisnet_database_healthy": int(bool((payload.get("database") or {}).get("healthy"))),
        "aegisnet_analysis_running": int(analysis.get("state") == "RUNNING"),
        "aegisnet_advisory_eligible": int(bool(advisory.get("eligible"))),
        "aegisnet_telemetry_heartbeat_age_seconds": float(telemetry.get("heartbeat_age_seconds") or 0.0),
        "aegisnet_telemetry_poll_error_fraction": float(telemetry.get("poll_error_fraction") or 0.0),
    }
    return "\n".join(f"{name} {value}" for name, value in values.items()) + "\n"


class Handler(BaseHTTPRequestHandler):
    server_version = "AegisNetHealth/1.0"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        payload = snapshot()
        if self.path == "/healthz":
            self._json(200 if payload["healthy"] else 503, payload)
            return
        if self.path == "/readyz":
            self._json(200 if payload["ready"] else 503, payload)
            return
        if self.path == "/metrics":
            body = prometheus(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._json(404, {"error": "not found", "paths": ["/healthz", "/readyz", "/metrics"]})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8510)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"AegisNet health endpoint listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
