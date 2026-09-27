#!/usr/bin/env python3
"""Start, stop, and inspect the AegisNet-WM continuous analysis service."""

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
SERVICE = Path(__file__).with_name("live_analysis_service.py")
PID_FILE = ROOT / "outputs" / "analysis-service.pid"
STATUS_FILE = ROOT / "outputs" / "analysis-status.json"
LOG_FILE = ROOT / "outputs" / "analysis-service.log"


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
        return (
            process
            if "python" in process.name().lower() and SERVICE.name.lower() in command
            else None
        )
    except psutil.Error:
        return None


def start() -> int:
    process = running_process()
    if process:
        print(f"Analysis service already running (PID {process.pid}).")
        return 0
    PID_FILE.unlink(missing_ok=True)
    ROOT.joinpath("outputs").mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(SERVICE), "--poll-seconds", "2"]
    with LOG_FILE.open("ab") as output:
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
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        time.sleep(0.25)
        process = running_process()
        if process:
            print(f"Analysis service started (PID {process.pid}).")
            return 0
        if child.poll() is not None:
            print(f"Analysis service exited with {child.returncode}; see {LOG_FILE}.", file=sys.stderr)
            return 1
    print(f"Analysis service failed to create PID file; see {LOG_FILE}.", file=sys.stderr)
    return 1


def stop() -> int:
    process = running_process()
    if not process:
        PID_FILE.unlink(missing_ok=True)
        print("Analysis service is not running.")
        return 0
    process.terminate()
    try:
        process.wait(timeout=10)
    except psutil.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    PID_FILE.unlink(missing_ok=True)
    print("Analysis service stopped.")
    return 0


def status() -> int:
    process = running_process()
    print(f"Process: {'running PID ' + str(process.pid) if process else 'stopped'}")
    if STATUS_FILE.exists():
        body = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
        print(json.dumps(body, indent=2))
        if process and body.get("state") == "FAILED_CLOSED":
            return 2
    return 0 if process else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("start")
    sub.add_parser("stop")
    sub.add_parser("status")
    args = parser.parse_args()
    if args.action == "start":
        return start()
    if args.action == "stop":
        return stop()
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
