from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from render_configs import COLLECTOR_IP, DEFAULT_SECRETS, MGMT, render_all  # noqa: E402
from push_configs import cli_commands  # noqa: E402


class TopologyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.topology = json.loads((ROOT / "lab" / "topology.json").read_text(encoding="utf-8"))

    def test_expected_inventory(self) -> None:
        kinds = Counter(node["kind"] for node in self.topology["nodes"])
        self.assertEqual(kinds, {"router": 9, "linux": 6})
        self.assertEqual(len(self.topology["networks"]), 19)

    def test_names_are_unique(self) -> None:
        node_names = [node["name"] for node in self.topology["nodes"]]
        network_names = [network["name"] for network in self.topology["networks"]]
        self.assertEqual(len(node_names), len(set(node_names)))
        self.assertEqual(len(network_names), len(set(network_names)))

    def test_every_connection_references_existing_objects(self) -> None:
        nodes = {node["name"] for node in self.topology["nodes"]}
        networks = {network["name"] for network in self.topology["networks"]}
        for connection in self.topology["connections"]:
            self.assertIn(connection["node"], nodes)
            self.assertIn(connection["network"], networks)

    def test_interfaces_are_not_double_booked(self) -> None:
        seen: set[tuple[str, int]] = set()
        for connection in self.topology["connections"]:
            key = (connection["node"], int(connection["interface"]))
            self.assertNotIn(key, seen)
            seen.add(key)

    def test_point_to_point_bridges_have_two_endpoints(self) -> None:
        network_types = {item["name"]: item["type"] for item in self.topology["networks"]}
        endpoints: dict[str, int] = defaultdict(int)
        for connection in self.topology["connections"]:
            endpoints[connection["network"]] += 1
        for name, network_type in network_types.items():
            if network_type == "bridge":
                self.assertEqual(endpoints[name], 2, name)
        self.assertGreater(endpoints["OOB-MGMT"], 2)

    def test_stock_netem_uses_both_nics_for_the_data_path(self) -> None:
        netems = {
            node["name"]: node
            for node in self.topology["nodes"]
            if node["name"].startswith("NETEM-")
        }
        self.assertTrue(all(node["ethernet"] == 2 for node in netems.values()))
        connections = {
            (item["node"], int(item["interface"]), item["network"])
            for item in self.topology["connections"]
        }
        self.assertNotIn(("NETEM-BR1-MPLS", 0, "OOB-MGMT"), connections)
        self.assertIn(("NETEM-BR1-MPLS", 0, "BR1-MPLS-A"), connections)
        self.assertIn(("NETEM-BR1-MPLS", 1, "BR1-MPLS-B"), connections)
        self.assertIn(("NETEM-BR1-INET", 0, "BR1-INET-A"), connections)
        self.assertIn(("NETEM-BR1-INET", 1, "BR1-INET-B"), connections)


class RouterConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.configs = render_all(DEFAULT_SECRETS)

    def test_all_router_configs_render(self) -> None:
        self.assertEqual(
            set(self.configs),
            {"P1", "P2", "PE1", "PE2", "INET", "HUB", "BR1", "BR2", "DC"},
        )

    def test_management_addresses_are_unique(self) -> None:
        self.assertEqual(len(MGMT), len(set(MGMT.values())))
        for hostname, address in MGMT.items():
            self.assertIn(f"ip address {address} 255.255.255.0", self.configs[hostname])

    def test_legacy_ios_local_secret_is_within_limit(self) -> None:
        for config in self.configs.values():
            match = re.search(
                r"^username noc privilege 15 secret 0 (\S+)$",
                config,
                re.MULTILINE,
            )
            self.assertIsNotNone(match)
            self.assertLessEqual(len(match.group(1)), 25)

    def test_provider_core_contains_mpls_l3vpn(self) -> None:
        for hostname in ("P1", "P2", "PE1", "PE2"):
            self.assertIn("mpls ldp router-id Loopback0 force", self.configs[hostname])
            self.assertIn("router ospf 10", self.configs[hostname])
        for hostname in ("PE1", "PE2"):
            self.assertIn("address-family vpnv4", self.configs[hostname])
            self.assertIn("route-target import 65000:100", self.configs[hostname])

    def test_dual_phase3_dmvpn(self) -> None:
        for hostname in ("HUB", "BR1", "BR2", "DC"):
            config = self.configs[hostname]
            self.assertIn("interface Tunnel100", config)
            self.assertIn("interface Tunnel200", config)
            self.assertIn("tunnel protection ipsec profile IPSEC-MPLS", config)
            self.assertIn("tunnel protection ipsec profile IPSEC-INET", config)
            self.assertIn("address-family ipv4 unicast autonomous-system 100", config)
            self.assertIn(
                "match identity remote address 10.100.0.0 255.255.0.0", config
            )
            self.assertIn(
                "match identity remote address 198.18.0.0 255.254.0.0", config
            )
        self.assertIn("ip nhrp redirect", self.configs["HUB"])
        for hostname in ("BR1", "BR2", "DC"):
            self.assertIn("ip nhrp shortcut", self.configs[hostname])

    def test_telemetry_targets_local_collector(self) -> None:
        for config in self.configs.values():
            self.assertIn(f"ip flow-export destination {COLLECTOR_IP} 2055", config)
            self.assertIn("ip flow-export template refresh-rate 1", config)
            self.assertIn(
                f"logging host {COLLECTOR_IP} transport udp port 5514", config
            )
            self.assertIn(
                f"snmp-server host {COLLECTOR_IP} version 3 priv copilot", config
            )

    def test_console_conversion_preserves_modes(self) -> None:
        commands = cli_commands(self.configs["HUB"])
        self.assertNotIn("version 15.2", commands)
        self.assertNotIn("!", commands)
        self.assertIn("configure terminal", ["configure terminal"])
        self.assertGreater(commands.count("exit"), 10)

    def test_branches_have_application_aware_path_policy(self) -> None:
        for hostname in ("BR1", "BR2"):
            config = self.configs[hostname]
            self.assertIn("ip policy route-map APP-STEER-DC", config)
            self.assertIn(
                "set ip next-hop verify-availability 172.20.100.20 10 track 111",
                config,
            )
            self.assertIn(
                "set ip next-hop verify-availability 172.20.200.20 10 track 112",
                config,
            )


if __name__ == "__main__":
    unittest.main()
