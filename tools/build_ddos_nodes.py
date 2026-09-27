#!/usr/bin/env python3
"""Create dual-NIC TinyCore nodes for the isolated DDoS training campaign."""

from __future__ import annotations

import sys
import uuid

from deploy_eve import EveClient, api_lab_path


NODES = {
    "DDOS-BR1": ("LAN-BR1", "58%", "58%"),
    "DDOS-BR2": ("LAN-BR2", "64%", "58%"),
    "DDOS-HUB": ("LAN-HUB", "58%", "20%"),
    "DDOS-VICTIM": ("LAN-DC", "64%", "20%"),
}


def main() -> int:
    client = EveClient("http://192.168.58.128")
    client.login("admin", "eve", native_console=True)
    endpoint = api_lab_path("/RS", "Air-Gapped Predictive Copilot")
    networks = client.request("GET", f"/labs{endpoint}/networks")["data"]
    network_ids = {network["name"]: int(key) for key, network in networks.items()}
    existing = client.request("GET", f"/labs{endpoint}/nodes")["data"]
    node_ids = {node["name"]: int(key) for key, node in existing.items()}

    for name, (service_network, left, top) in NODES.items():
        node_id = node_ids.get(name)
        if node_id is None:
            payload = {
                "type": "qemu",
                "template": "linux",
                "config": "0",
                "delay": 0,
                "icon": "Server.png",
                "image": "linux-tinycore-6.4",
                "name": name,
                "left": left,
                "top": top,
                "ram": "128",
                "console": "telnet",
                "cpu": 1,
                "ethernet": 2,
                "uuid": str(uuid.uuid4()),
            }
            client.request("POST", f"/labs{endpoint}/nodes", payload)
            current = client.request("GET", f"/labs{endpoint}/nodes")["data"]
            node_id = next(int(key) for key, node in current.items() if node["name"] == name)

        client.request(
            "PUT",
            f"/labs{endpoint}/nodes/{node_id}/interfaces",
            {"0": network_ids["OOB-MGMT"], "1": network_ids[service_network]},
        )
        client.request("GET", f"/labs{endpoint}/nodes/{node_id}/start")
        print(f"{name}: node_id={node_id} service={service_network}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
