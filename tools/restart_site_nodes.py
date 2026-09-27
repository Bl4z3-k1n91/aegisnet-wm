#!/usr/bin/env python3
"""Restart only the four site routers in the EVE lab to restore runtime state."""

from __future__ import annotations

import time

from deploy_eve import EveClient, api_lab_path


SITE_NAMES = ("HUB", "BR1", "BR2", "DC")


def main() -> int:
    client = EveClient("http://192.168.58.128")
    client.login("admin", "eve", native_console=True)
    endpoint = api_lab_path("/RS", "Air-Gapped Predictive Copilot")
    nodes = client.request("GET", f"/labs{endpoint}/nodes")["data"]
    node_ids = {
        node["name"]: int(key)
        for key, node in nodes.items()
        if node["name"] in SITE_NAMES
    }
    missing = [name for name in SITE_NAMES if name not in node_ids]
    if missing:
        raise RuntimeError(f"missing site nodes: {', '.join(missing)}")

    for name in SITE_NAMES:
        client.request("GET", f"/labs{endpoint}/nodes/{node_ids[name]}/stop")
        print(f"{name}: stopped")
    time.sleep(3)
    for name in SITE_NAMES:
        client.request("GET", f"/labs{endpoint}/nodes/{node_ids[name]}/start")
        print(f"{name}: started")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
