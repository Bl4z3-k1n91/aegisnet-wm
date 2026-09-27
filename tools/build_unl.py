#!/usr/bin/env python3
"""Build an EVE-NG 2.0-compatible .unl file from lab/topology.json."""

from __future__ import annotations

import argparse
import json
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TOPOLOGY = ROOT / "lab" / "topology.json"
DEFAULT_OUTPUT = ROOT / "eve" / "air-gapped-predictive-copilot.unl"


def coordinate(value: str | int, extent: int) -> str:
    if isinstance(value, int):
        return str(value)
    if value.endswith("%"):
        return str(round(float(value[:-1]) * extent / 100))
    return str(int(value))


def interface_name(kind: str, interface_id: int) -> str:
    return f"fa{interface_id}/0" if kind == "router" else f"e{interface_id}"


def router_node(
    parent: ET.Element,
    node_id: int,
    node: dict[str, Any],
    defaults: dict[str, Any],
    interfaces: list[dict[str, Any]],
    network_ids: dict[str, int],
    router_image: str,
) -> None:
    idlepc = defaults["idlepc_by_image"].get(router_image, "0x0")
    element = ET.SubElement(
        parent,
        "node",
        {
            "id": str(node_id),
            "name": node["name"],
            "type": "dynamips",
            "template": defaults["router_template"],
            "image": router_image,
            "idlepc": idlepc,
            "nvram": str(defaults["router_nvram"]),
            "ram": str(defaults["router_ram"]),
            "console": "",
            "delay": "0",
            "icon": "Router.png",
            "config": "0",
            "left": coordinate(node["left"], 1024),
            "top": coordinate(node["top"], 768),
        },
    )
    for slot, module in defaults["router_slots"].items():
        ET.SubElement(
            element,
            "slot",
            {"id": slot.removeprefix("slot"), "module": module},
        )
    for connection in sorted(interfaces, key=lambda item: int(item["interface"])):
        logical_interface = int(connection["interface"])
        # EVE/Dynamips encodes PA slot N port 0 as N * 16.
        interface_id = logical_interface * 16
        ET.SubElement(
            element,
            "interface",
            {
                "id": str(interface_id),
                "name": interface_name("router", logical_interface),
                "type": "ethernet",
                "network_id": str(network_ids[connection["network"]]),
            },
        )


def linux_node(
    parent: ET.Element,
    node_id: int,
    node: dict[str, Any],
    defaults: dict[str, Any],
    interfaces: list[dict[str, Any]],
    network_ids: dict[str, int],
    netem_image: str,
    endpoint_image: str,
) -> None:
    is_netem = node["name"].startswith("NETEM-")
    image = netem_image if is_netem else endpoint_image
    ram = defaults["netem_ram"] if is_netem else defaults["endpoint_ram"]
    node_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"copilot-lab:{node['name']}")
    element = ET.SubElement(
        parent,
        "node",
        {
            "id": str(node_id),
            "name": node["name"],
            "type": "qemu",
            "template": defaults["linux_template"],
            "image": image,
            "console": "telnet",
            "cpu": "1",
            "cpulimit": "1",
            "ram": str(ram),
            "ethernet": str(node.get("ethernet", 1)),
            "uuid": str(node_uuid),
            "firstmac": f"00:50:00:00:{node_id:02x}:00",
            "qemu_options": "-machine type=pc,accel=kvm -vga virtio -usbdevice tablet -boot order=cd",
            "qemu_version": "2.12.0",
            "qemu_arch": "x86_64",
            "qemu_nic": "virtio-net-pci",
            "delay": "0",
            "icon": "Server.png",
            "config": "0",
            "left": coordinate(node["left"], 1024),
            "top": coordinate(node["top"], 768),
        },
    )
    for connection in sorted(interfaces, key=lambda item: int(item["interface"])):
        interface_id = int(connection["interface"])
        ET.SubElement(
            element,
            "interface",
            {
                "id": str(interface_id),
                "name": interface_name("linux", interface_id),
                "type": "ethernet",
                "network_id": str(network_ids[connection["network"]]),
            },
        )


def build(
    topology: dict[str, Any],
    *,
    router_image: str,
    netem_image: str,
    endpoint_image: str,
) -> ET.ElementTree:
    lab_info = topology["lab"]
    lab = ET.Element(
        "lab",
        {
            "name": lab_info["name"],
            "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "air-gapped-predictive-copilot")),
            "version": "1",
            "scripttimeout": "600",
            "lock": "0",
        },
    )
    ET.SubElement(lab, "description").text = lab_info["description"]
    ET.SubElement(lab, "body").text = (
        "Dual DMVPN Phase 3 clouds over MPLS L3VPN and simulated Internet. "
        "Generated from the Air-Gapped Predictive Copilot workspace."
    )
    topology_element = ET.SubElement(lab, "topology")
    nodes_element = ET.SubElement(topology_element, "nodes")
    networks_element = ET.SubElement(topology_element, "networks")

    network_ids = {
        network["name"]: index
        for index, network in enumerate(topology["networks"], start=1)
    }
    connections_by_node: dict[str, list[dict[str, Any]]] = {
        node["name"]: [] for node in topology["nodes"]
    }
    for connection in topology["connections"]:
        connections_by_node[connection["node"]].append(connection)

    defaults = topology["defaults"]
    for node_id, node in enumerate(topology["nodes"], start=1):
        if node["kind"] == "router":
            router_node(
                nodes_element,
                node_id,
                node,
                defaults,
                connections_by_node[node["name"]],
                network_ids,
                router_image,
            )
        else:
            linux_node(
                nodes_element,
                node_id,
                node,
                defaults,
                connections_by_node[node["name"]],
                network_ids,
                netem_image,
                endpoint_image,
            )

    for network_id, network in enumerate(topology["networks"], start=1):
        ET.SubElement(
            networks_element,
            "network",
            {
                "id": str(network_id),
                "type": network["type"],
                "name": network["name"],
                "left": coordinate(network["left"], 1024),
                "top": coordinate(network["top"], 768),
                "visibility": "1",
            },
        )
    ET.indent(lab, space="  ")
    return ET.ElementTree(lab)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topology", type=Path, default=DEFAULT_TOPOLOGY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--router-image",
        default="c7200-adventerprisek9-mz.152-4.S7.image",
    )
    parser.add_argument("--netem-image", default="linux-netem")
    parser.add_argument("--endpoint-image", default="linux-tinycore-6.4")
    args = parser.parse_args()

    topology = json.loads(args.topology.read_text(encoding="utf-8"))
    tree = build(
        topology,
        router_image=args.router_image,
        netem_image=args.netem_image,
        endpoint_image=args.endpoint_image,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tree.write(args.output, encoding="UTF-8", xml_declaration=True)
    ET.parse(args.output)
    print(f"Built and validated {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
