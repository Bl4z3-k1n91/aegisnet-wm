#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import psutil


ROOT = Path(__file__).resolve().parents[1]
SERVICE = Path(__file__).with_name("health_server.py")
PID_FILE = ROOT / "outputs" / "health-service.pid"
LOG_FILE = ROOT / "outputs" / "health-service.log"


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


def start() -> int:
    process = running_process()
    if process:
        print(f"Health service already running (PID {process.pid}).")
        return 0
    PID_FILE.unlink(missing_ok=True)
    ROOT.joinpath("outputs").mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(SERVICE)]
    with LOG_FILE.open("ab") as output:
        kwargs: dict[str, object] = {
            "cwd": str(ROOT),
            "stdin": subprocess.DEVNULL,
            "stdout": output,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        child = subprocess.Popen(command, **kwargs)
    PID_FILE.write_text(str(child.pid), encoding="ascii")
    time.sleep(0.5)
    if child.poll() is not None:
        PID_FILE.unlink(missing_ok=True)
        print(f"Health service exited with {child.returncode}; see {LOG_FILE}.", file=sys.stderr)
        return 1
    print(f"Health service started (PID {child.pid}).")
    return 0


def stop() -> int:
    process = running_process()
    if not process:
        PID_FILE.unlink(missing_ok=True)
        print("Health service is not running.")
        return 0
    process.terminate()
    try:
        process.wait(timeout=5)
    except psutil.TimeoutExpired:
        process.kill()
    PID_FILE.unlink(missing_ok=True)
    print("Health service stopped.")
    return 0


def status() -> int:
    process = running_process()
    print(f"Process: {'running PID ' + str(process.pid) if process else 'stopped'}")
    return 0 if process else 1


def main() -> int:
    parser = argparse.ArgumentParser()
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
