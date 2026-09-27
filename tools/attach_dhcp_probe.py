#!/usr/bin/env python3
"""Attach the temporary DHCP-PROBE node to OOB-MGMT and start it."""

from __future__ import annotations

import sys

from deploy_eve import EveClient, api_lab_path


def main() -> int:
    client = EveClient("http://192.168.58.128")
    client.login("admin", "eve", native_console=True)
    endpoint = api_lab_path("/RS", "Air-Gapped Predictive Copilot")
    nodes = client.request("GET", f"/labs{endpoint}/nodes")["data"]
    networks = client.request("GET", f"/labs{endpoint}/networks")["data"]
    node_id = next(int(key) for key, node in nodes.items() if node["name"] == "DHCP-PROBE")
    network_id = next(
        int(key) for key, network in networks.items() if network["name"] == "OOB-MGMT"
    )
    client.request(
        "PUT",
        f"/labs{endpoint}/nodes/{node_id}/interfaces",
        {"0": network_id},
    )
    client.request("GET", f"/labs{endpoint}/nodes/{node_id}/start")
    print(f"DHCP-PROBE node_id={node_id} attached_to={network_id} and started")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
