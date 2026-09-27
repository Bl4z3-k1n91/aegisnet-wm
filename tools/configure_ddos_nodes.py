#!/usr/bin/env python3
"""Install iperf3 and configure the isolated DDoS lab nodes."""

from __future__ import annotations

import sys
import time

from push_configs import TelnetConsole


NODES = {
    "DDOS-BR1": {
        "port": 32785,
        "service_ip": "10.1.10.50",
        "gateway": "10.1.10.1",
        "routes": (("10.20.10.0", "10.1.10.1"),),
    },
    "DDOS-BR2": {
        "port": 32786,
        "service_ip": "10.2.10.50",
        "gateway": "10.2.10.1",
        "routes": (("10.20.10.0", "10.2.10.1"),),
    },
    "DDOS-HUB": {
        "port": 32787,
        "service_ip": "10.10.10.50",
        "gateway": "10.10.10.1",
        "routes": (("10.20.10.0", "10.10.10.1"),),
    },
    "DDOS-VICTIM": {
        "port": 32788,
        "service_ip": "10.20.10.50",
        "gateway": "10.20.10.1",
        "routes": (
            ("10.1.10.0", "10.20.10.1"),
            ("10.2.10.0", "10.20.10.1"),
            ("10.10.10.0", "10.20.10.1"),
        ),
    },
}


def login(console: TelnetConsole) -> None:
    console.send("\r")
    time.sleep(0.4)
    output = console.read_available(0.8)
    if "login:" in output:
        console.send("gns3\r")
        time.sleep(0.3)
        console.read_available(0.5)
        console.send("gns3\r")
        time.sleep(0.5)
        console.read_available(0.8)


def command(console: TelnetConsole, text: str, wait: float = 0.8) -> str:
    console.send(text + "\r")
    time.sleep(wait)
    return console.read_available(1.2)


def main() -> int:
    for name, config in NODES.items():
        console = TelnetConsole("192.168.58.128", int(config["port"]))
        try:
            login(console)
            print(f"[{name}] installing iperf3")
            output = command(console, "tce-load -wi iperf3.tcz", 12.0)
            if "Error on iperf3.tcz" in output:
                raise RuntimeError(f"{name}: iperf3 install failed: {output}")

            service_ip = str(config["service_ip"])
            command(
                console,
                f"sudo ifconfig eth1 {service_ip} netmask 255.255.255.0 up",
                0.8,
            )
            for network, gateway in config["routes"]:
                command(
                    console,
                    f"sudo route add -net {network} netmask 255.255.255.0 gw {gateway} 2>/dev/null || true",
                    0.5,
                )

            print(command(console, "ifconfig eth0", 0.6))
            print(command(console, "ifconfig eth1", 0.6))
            print(command(console, "route -n", 0.6))
            print(command(console, "iperf3 --version", 0.6))

            if name == "DDOS-VICTIM":
                command(console, "pkill iperf3 2>/dev/null || true", 0.4)
                print(command(console, "iperf3 -s -D -p 5201", 0.8))
        finally:
            console.close()

    for name in ("DDOS-BR1", "DDOS-BR2", "DDOS-HUB"):
        config = NODES[name]
        console = TelnetConsole("192.168.58.128", int(config["port"]))
        try:
            login(console)
            print(f"[{name}] path test")
            print(command(console, "ping -c 2 10.20.10.50", 3.0))
            print(
                command(
                    console,
                    "iperf3 -c 10.20.10.50 -p 5201 -u -b 1M -t 3",
                    5.0,
                )
            )
        finally:
            console.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
