#!/usr/bin/env python3
"""Start, stop and inspect the unified telemetry service."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil


ROOT = Path(__file__).resolve().parents[1]
SERVICE = Path(__file__).with_name("telemetry_service.py")
PID_FILE = ROOT / "outputs" / "telemetry-service.pid"
STATUS_FILE = ROOT / "outputs" / "telemetry-status.json"
LAUNCH_LOG = ROOT / "outputs" / "telemetry-launch.log"


def read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError):
        return None


def running_process() -> psutil.Process | None:
    pid = read_pid()
    if pid is None:
        return None
    try:
        process = psutil.Process(pid)
        command = " ".join(process.cmdline()).lower()
        if "python" not in process.name().lower() or SERVICE.name.lower() not in command:
            return None
        return process
    except psutil.Error:
        return None


def start(extra: list[str]) -> int:
    process = running_process()
    if process:
        print(f"Telemetry service is already running (PID {process.pid}).")
        return 0
    PID_FILE.unlink(missing_ok=True)
    ROOT.joinpath("outputs").mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(SERVICE), *extra]
    with LAUNCH_LOG.open("ab") as output:
        kwargs: dict[str, object] = {
            "cwd": str(ROOT),
            "stdin": subprocess.DEVNULL,
            "stdout": output,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP
                | subprocess.DETACHED_PROCESS
                | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True
        child = subprocess.Popen(command, **kwargs)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        time.sleep(0.25)
        process = running_process()
        if process:
            print(f"Telemetry service started (PID {process.pid}).")
            return 0
        if child.poll() is not None:
            print(
                f"Telemetry service exited with status {child.returncode}; "
                f"see {LAUNCH_LOG}.",
                file=sys.stderr,
            )
            return 1
    print(f"Service did not create {PID_FILE}; see {LAUNCH_LOG}.", file=sys.stderr)
    return 1


def stop() -> int:
    process = running_process()
    if not process:
        PID_FILE.unlink(missing_ok=True)
        print("Telemetry service is not running.")
        return 0
    process.terminate()
    try:
        process.wait(timeout=15)
    except psutil.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    PID_FILE.unlink(missing_ok=True)
    print("Telemetry service stopped.")
    return 0


def status() -> int:
    process = running_process()
    print(
        f"Process: {'running PID ' + str(process.pid) if process else 'stopped'}"
    )
    if STATUS_FILE.is_file():
        body = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        print(json.dumps(body, indent=2))
        if process and body.get("health") == "FAILED":
            return 2
    else:
        print(f"No status file yet: {STATUS_FILE}")
    return 0 if process else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    start_parser = subparsers.add_parser("start")
    start_parser.add_argument(
        "service_args",
        nargs=argparse.REMAINDER,
        help="Arguments passed to telemetry_service.py after '--'.",
    )
    subparsers.add_parser("stop")
    subparsers.add_parser("status")
    args = parser.parse_args()
    if args.action == "start":
        extra = args.service_args
        if extra[:1] == ["--"]:
            extra = extra[1:]
        return start(extra)
    if args.action == "stop":
        return stop()
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
