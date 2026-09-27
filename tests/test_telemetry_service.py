from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))

from ios_telemetry import (
    PollResult,
    parse_device_state,
    parse_interfaces,
    parse_qos,
    parse_sla,
)
from telemetry_store import TelemetryStore


SLA_OUTPUT = """
IPSLA operation id: 101
    Latest RTT: 56 milliseconds
Latest operation return code: OK
Number of successes: 493
Number of failures: 13
Operation time to live: Forever

IPSLA operation id: 102
    Latest RTT: 40 milliseconds
Latest operation return code: Timeout
Number of successes: 490
Number of failures: 16
"""

TRACK_OUTPUT = """
101     ip sla      101                  reachability     Up    00:41:02
102     ip sla      102                  reachability     Down  00:00:04
"""

INTERFACE_OUTPUT = """
FastEthernet1/0 is up, line protocol is up
  Input queue: 0/75/3/0 (size/max/drops/flushes); Total output drops: 7
  5 minute input rate 12000 bits/sec, 4 packets/sec
  5 minute output rate 8000 bits/sec, 3 packets/sec
     2 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     1 output errors, 0 collisions, 0 interface resets
Tunnel100 is administratively down, line protocol is down
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 9
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 0 interface resets
"""


class ParserTests(unittest.TestCase):
    def test_qos_parser(self) -> None:
        output = """
 FastEthernet1/0
  Service-policy output: WAN-SHAPER
    Class-map: class-default (match-any)
      100 packets, 50000 bytes
      5 minute offered rate 12000 bps, drop rate 1000 bps
      (queue depth/total drops/no-buffer drops) 0/7/0
      target shape rate 5000000
      Service-policy : CHILD-QOS
        Class-map: VOICE (match-any)
          20 packets, 18000 bytes
          5 minute offered rate 4000 bps, drop rate 0 bps
"""
        rows = parse_qos(output)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["policy"], "WAN-SHAPER")
        self.assertEqual(rows[0]["total_drops"], 7)
        self.assertEqual(rows[0]["shape_rate"], 5000000)
        self.assertEqual(rows[1]["policy"], "CHILD-QOS")
        self.assertEqual(rows[1]["class_name"], "VOICE")

    def test_sla_and_track_parser(self) -> None:
        samples = parse_sla(SLA_OUTPUT, TRACK_OUTPUT)
        self.assertEqual(samples[0]["operation_id"], 101)
        self.assertEqual(samples[0]["rtt_ms"], 56)
        self.assertEqual(samples[0]["track_state"], "Up")
        self.assertEqual(samples[1]["return_code"], "Timeout")
        self.assertEqual(samples[1]["track_state"], "Down")

    def test_interface_parser(self) -> None:
        samples = parse_interfaces(INTERFACE_OUTPUT)
        self.assertEqual(len(samples), 2)
        first = samples[0]
        self.assertEqual(first["interface"], "FastEthernet1/0")
        self.assertEqual(first["input_bps"], 12000)
        self.assertEqual(first["input_drops"], 3)
        self.assertEqual(first["output_drops"], 7)
        self.assertEqual(first["input_errors"], 2)
        self.assertEqual(samples[1]["admin_state"], "administratively down")

    def test_device_state_parser(self) -> None:
        state = parse_device_state(
            {
                "cpu": (
                    "CPU utilization for five seconds: 14%/0%; "
                    "one minute: 18%; five minutes: 20%"
                ),
                "memory": (
                    "Processor 65AF3200 391170732 62007396 "
                    "329163336 328574616 324061868"
                ),
                "bgp": (
                    "10.0.0.1 4 65000 10 10 1 0 0 00:10:00 4\n"
                    "10.0.0.2 4 65000 10 10 1 0 0 00:10:00 Idle"
                ),
                "ospf": "10.0.0.1 1 FULL/DR 00:00:30",
                "eigrp": "0 172.20.100.1 Tu100 12 00:01:00 5 100 0 3",
                "dmvpn": "1 10.0.0.1 172.20.100.1 UP 00:01:00 S",
                "ikev2": "1 10.0.0.1/500 10.0.0.2/500 none/none READY",
            }
        )
        self.assertEqual(state["cpu_5s"], 14)
        self.assertEqual(state["memory_total"], 391170732)
        self.assertEqual(state["bgp_established"], 1)
        self.assertEqual(state["dmvpn_up"], 1)
        self.assertEqual(state["ikev2_ready"], 1)

    def test_device_state_parser_current_ios_commands(self) -> None:
        state = parse_device_state(
            {
                "nhrp": """
172.20.100.1/32 via 172.20.100.1
   Type: static, Flags: used
172.20.100.20/32 via 172.20.100.20
   Type: dynamic, Flags: router implicit used
172.20.200.20/32 via 172.20.200.20
   Type: dynamic, Flags: router implicit used
""",
                "crypto_session": """
Interface: Tunnel100
Session status: UP-ACTIVE
Interface: Tunnel200
Session status: UP-ACTIVE
""",
            }
        )
        self.assertEqual(state["dmvpn_up"], 2)
        self.assertEqual(state["ikev2_ready"], 2)


class StorageTests(unittest.TestCase):
    def test_poll_and_flow_storage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telemetry.db"
            store = TelemetryStore(path)
            poll = PollResult(
                device="BR1",
                management_ip="10.0.0.1",
                poll_ms=100,
                sla=parse_sla(SLA_OUTPUT, TRACK_OUTPUT),
                interfaces=parse_interfaces(INTERFACE_OUTPUT),
                state={"bgp_established": 2},
            )
            store.write_poll(poll)
            store.write_flows(
                [
                    {
                        "timestamp": "2026-01-01T00:00:00+00:00",
                        "exporter": "10.0.0.1",
                        "version": 9,
                        "src_ip": "10.1.1.1",
                        "dst_ip": "10.2.2.2",
                        "src_port": 40000,
                        "dst_port": 443,
                        "protocol": 6,
                        "tcp_flags": 0x12,
                        "direction": 0,
                        "next_hop": "10.0.0.2",
                        "bytes": 100,
                        "packets": 1,
                        "flow_start_uptime_ms": 1000,
                        "flow_end_uptime_ms": 1250,
                    }
                ],
                {"10.0.0.1": "BR1"},
            )
            counts = store.counts()
            self.assertEqual(counts["sla_samples"], 2)
            self.assertEqual(counts["interface_samples"], 2)
            self.assertEqual(counts["device_samples"], 1)
            self.assertEqual(counts["flows"], 1)
            store.close()
            connection = sqlite3.connect(path)
            self.assertEqual(
                connection.execute("SELECT device FROM flows").fetchone()[0],
                "BR1",
            )
            row = connection.execute(
                """
                SELECT tcp_flags,direction,next_hop,flow_start_uptime_ms,
                       flow_end_uptime_ms FROM flows
                """
            ).fetchone()
            self.assertEqual(row, (0x12, 0, "10.0.0.2", 1000, 1250))
            connection.close()


if __name__ == "__main__":
    unittest.main()
