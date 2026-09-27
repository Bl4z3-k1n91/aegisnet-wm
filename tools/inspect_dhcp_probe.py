#!/usr/bin/env python3
"""Inspect DHCP, routing, DNS and Internet reachability on DHCP-PROBE."""

from __future__ import annotations

import sys
import time

from push_configs import TelnetConsole


def main() -> int:
    console = TelnetConsole("192.168.58.128", 32784)
    try:
        console.send("\r")
        time.sleep(0.5)
        output = console.read_available(1.0)
        if "login:" in output:
            console.send("gns3\r")
            time.sleep(0.4)
            console.read_available(0.6)
            console.send("gns3\r")
            time.sleep(0.6)
            console.read_available(0.8)
        for command, delay in (
            ("ifconfig eth0", 0.8),
            ("route -n", 0.8),
            ("cat /etc/resolv.conf", 0.6),
            ("ping -c 2 192.168.58.2", 2.5),
            ("ping -c 2 8.8.8.8", 2.5),
            ("nslookup repo.tinycorelinux.net", 2.5),
        ):
            console.send(command + "\r")
            time.sleep(delay)
            print(f"--- {command} ---")
            print(console.read_available(1.2))
    finally:
        console.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
