#!/usr/bin/env python3
"""Bounce DMVPN tunnel interfaces on the four site routers without saving changes."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from audit_lab import load_dotenv, run_console
from push_configs import TelnetConsole


ROOT = Path(__file__).resolve().parents[1]
ROUTERS = (("HUB", 32774), ("BR1", 32775), ("BR2", 32776), ("DC", 32777))


def enable(console: TelnetConsole, secret: str) -> None:
    prompt = console.initialize_ios()
    if prompt.rstrip().endswith(">"):
        console.send("enable\r")
        time.sleep(0.25)
        console.read_available(0.4)
        console.send(secret + "\r")
        time.sleep(0.4)
        if "#" not in console.read_available(0.7):
            raise RuntimeError("failed to enter privileged mode")


def set_state(shutdown: bool, secret: str) -> None:
    action = "shutdown" if shutdown else "no shutdown"
    for name, port in ROUTERS:
        console = TelnetConsole("192.168.58.128", port)
        try:
            enable(console, secret)
            for command in (
                "configure terminal",
                "interface Tunnel100",
                action,
                "interface Tunnel200",
                action,
                "end",
            ):
                run_console(console, command, 0.3)
            print(f"{name}: {action}")
        finally:
            console.close()


def main() -> int:
    load_dotenv(ROOT / ".env")
    secret = os.environ["LAB_ENABLE_SECRET"]
    set_state(True, secret)
    time.sleep(2)
    set_state(False, secret)
    print("overlay reset complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
