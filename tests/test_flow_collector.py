from __future__ import annotations

import struct
import sys
import unittest
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "telemetry"))

from flow_collector import FlowParser  # noqa: E402


def make_v9_packet(template_id: int = 256) -> bytes:
    fields = [
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (2, 4),
    ]
    template_record = struct.pack("!HH", template_id, len(fields)) + b"".join(
        struct.pack("!HH", field, length) for field, length in fields
    )
    template_set = struct.pack("!HH", 0, 4 + len(template_record)) + template_record
    record = (
        bytes((10, 1, 10, 10))
        + bytes((10, 20, 10, 10))
        + struct.pack("!HHBII", 12345, 5201, 6, 98765, 321)
    )
    data_set = struct.pack("!HH", template_id, 4 + len(record)) + record
    header = struct.pack("!HHIIII", 9, 1, 1000, 1_700_000_000, 42, 7)
    return header + template_set + data_set


def make_v9_timed_packet(template_id: int = 257) -> bytes:
    fields = [
        (8, 4),
        (12, 4),
        (7, 2),
        (11, 2),
        (4, 1),
        (1, 4),
        (2, 4),
        (22, 4),
        (21, 4),
    ]
    template_record = struct.pack("!HH", template_id, len(fields)) + b"".join(
        struct.pack("!HH", field, length) for field, length in fields
    )
    template_set = struct.pack("!HH", 0, 4 + len(template_record)) + template_record
    record = (
        bytes((10, 1, 10, 10))
        + bytes((10, 20, 10, 10))
        + struct.pack("!HHBIIII", 12345, 5201, 17, 98765, 321, 8000, 9000)
    )
    data_set = struct.pack("!HH", template_id, 4 + len(record)) + record
    header = struct.pack("!HHIIII", 9, 1, 10000, 1_700_000_000, 43, 7)
    return header + template_set + data_set


def make_ipfix_packet(template_id: int = 300) -> bytes:
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (1, 8), (2, 8)]
    template_record = struct.pack("!HH", template_id, len(fields)) + b"".join(
        struct.pack("!HH", field, length) for field, length in fields
    )
    template_set = struct.pack("!HH", 2, 4 + len(template_record)) + template_record
    record = (
        bytes((10, 2, 10, 10))
        + bytes((10, 20, 10, 10))
        + struct.pack("!HHQQ", 32000, 5202, 123456, 789)
    )
    data_set = struct.pack("!HH", template_id, 4 + len(record)) + record
    length = 16 + len(template_set) + len(data_set)
    header = struct.pack("!HHIII", 10, length, 1_700_000_000, 88, 9)
    return header + template_set + data_set


class FlowCollectorTests(unittest.TestCase):
    def test_v9_template_and_record(self) -> None:
        parser = FlowParser()
        records = parser.parse_packet(make_v9_packet(), "172.31.255.101")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["src_ip"], "10.1.10.10")
        self.assertEqual(record["dst_ip"], "10.20.10.10")
        self.assertEqual(record["src_port"], 12345)
        self.assertEqual(record["dst_port"], 5201)
        self.assertEqual(record["protocol"], 6)
        self.assertEqual(record["bytes"], 98765)
        self.assertEqual(record["packets"], 321)
        self.assertEqual(record["observation_domain"], 7)

    def test_templates_are_scoped_per_exporter(self) -> None:
        parser = FlowParser()
        packet = make_v9_packet()
        parser.parse_packet(packet, "172.31.255.101")
        parser.parse_packet(packet, "172.31.255.102")
        exporters = {key[1] for key in parser.templates}
        self.assertEqual(exporters, {"172.31.255.101", "172.31.255.102"})

    def test_v9_uptime_reconstructs_absolute_flow_times(self) -> None:
        parser = FlowParser()
        record = parser.parse_packet(make_v9_timed_packet(), "172.31.255.101")[0]
        received = datetime.fromisoformat(record["timestamp"])
        start = datetime.fromisoformat(record["flow_start"])
        end = datetime.fromisoformat(record["flow_end"])
        self.assertEqual(record["system_uptime_ms"], 10000)
        self.assertAlmostEqual((received - start).total_seconds(), 2.0, places=2)
        self.assertAlmostEqual((received - end).total_seconds(), 1.0, places=2)

    def test_ipfix_template_and_record(self) -> None:
        parser = FlowParser()
        records = parser.parse_packet(make_ipfix_packet(), "172.31.255.120")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["version"], 10)
        self.assertEqual(records[0]["src_ip"], "10.2.10.10")
        self.assertEqual(records[0]["dst_port"], 5202)
        self.assertEqual(records[0]["bytes"], 123456)

    def test_unknown_version_is_ignored(self) -> None:
        parser = FlowParser()
        self.assertEqual(parser.parse_packet(struct.pack("!H", 5) + b"\0" * 30, "x"), [])


if __name__ == "__main__":
    unittest.main()
