#!/usr/bin/env python3
"""Install iperf3 on the Internet-connected DHCP-PROBE TinyCore node."""

from __future__ import annotations

import sys
import time

from push_configs import TelnetConsole


def run(console: TelnetConsole, command: str, wait: float = 1.0) -> str:
    console.send(command + "\r")
    time.sleep(wait)
    return console.read_available(1.5)


def main() -> int:
    console = TelnetConsole("192.168.58.128", 32784)
    try:
        console.send("\r")
        time.sleep(0.4)
        output = console.read_available(0.8)
        if "login:" in output:
            console.send("gns3\r")
            time.sleep(0.3)
            console.read_available(0.5)
            console.send("gns3\r")
            time.sleep(0.5)
            console.read_available(0.6)

        print(run(console, "tce-load -wi iperf3.tcz", 15.0))
        print(run(console, "iperf3 --version", 1.0))
        print(run(console, "ls -1 /etc/sysconfig/tcedir/optional | tail -n 20", 1.0))
    finally:
        console.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
