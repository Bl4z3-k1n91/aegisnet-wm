from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from build_unl import build  # noqa: E402


class UnlBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        topology = json.loads((ROOT / "lab" / "topology.json").read_text())
        cls.root = build(
            topology,
            router_image="c7200-adventerprisek9-mz.152-4.S7.image",
            netem_image="linux-netem",
            endpoint_image="linux-tinycore-6.4",
        ).getroot()

    def test_inventory(self) -> None:
        self.assertEqual(len(self.root.findall("./topology/nodes/node")), 15)
        self.assertEqual(len(self.root.findall("./topology/networks/network")), 19)

    def test_every_bridge_has_two_attachments(self) -> None:
        attachments: dict[str, int] = {}
        for interface in self.root.findall(".//interface"):
            network_id = interface.attrib["network_id"]
            attachments[network_id] = attachments.get(network_id, 0) + 1
        for network in self.root.findall("./topology/networks/network"):
            if network.attrib["type"] == "bridge":
                self.assertEqual(attachments[network.attrib["id"]], 2)

    def test_s7_idlepc_and_pnet0(self) -> None:
        routers = [
            node
            for node in self.root.findall("./topology/nodes/node")
            if node.attrib["type"] == "dynamips"
        ]
        self.assertTrue(all(node.attrib["idlepc"] == "0x62f21000" for node in routers))
        mgmt = self.root.find("./topology/networks/network[@name='OOB-MGMT']")
        self.assertIsNotNone(mgmt)
        self.assertEqual(mgmt.attrib["type"], "pnet0")

    def test_linux_nodes_are_controllable_over_serial_console(self) -> None:
        linux_nodes = [
            node
            for node in self.root.findall("./topology/nodes/node")
            if node.attrib["type"] == "qemu"
        ]
        self.assertEqual(len(linux_nodes), 6)
        self.assertTrue(
            all(node.attrib["console"] == "telnet" for node in linux_nodes)
        )

    def test_dynamips_port_adapter_ids_are_slot_times_sixteen(self) -> None:
        p1 = self.root.find("./topology/nodes/node[@name='P1']")
        ids = {item.attrib["id"] for item in p1.findall("interface")}
        self.assertEqual(ids, {"0", "16", "32"})


if __name__ == "__main__":
    unittest.main()
