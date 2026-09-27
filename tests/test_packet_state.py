from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap  # type: ignore[import-untyped]


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from features.packet_state import (  # noqa: E402
    aggregate_packet_state,
    build_packet_state_windows,
    mark_tcp_retransmissions,
    read_pcap_events,
)


class PacketStateTests(unittest.TestCase):
    def test_pcap_metadata_and_retransmission_features(self) -> None:
        packets = []
        definitions = [
            (1.0, 64, 4096, 100, b"hello", "DF"),
            (1.1, 63, 4096, 105, b"world", "DF"),
            # Same directional flow, sequence and payload length as packet 2.
            (1.2, 63, 2048, 105, b"WORLD", "MF"),
        ]
        for timestamp, ttl, window, sequence, payload, flags in definitions:
            packet = (
                Ether()
                / IP(src="10.1.10.10", dst="10.20.10.10", ttl=ttl, flags=flags)
                / TCP(sport=40000, dport=445, flags="PA", seq=sequence, window=window)
                / Raw(payload)
            )
            packet.time = timestamp
            packets.append(packet)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pcap"
            wrpcap(str(path), packets)
            events = read_pcap_events(path)

        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["ttl"], 64)
        self.assertEqual(events[0]["tcp_window"], 4096)
        self.assertEqual(events[0]["payload_bytes"], 5)
        self.assertEqual(events[2]["more_fragments"], 1)

        marked = mark_tcp_retransmissions(events)
        self.assertEqual([event["retransmission"] for event in marked], [0, 0, 1])

        state = aggregate_packet_state(events)
        self.assertEqual(state["packet_event_count"], 3)
        self.assertEqual(state["retransmission_count"], 1)
        self.assertEqual(state["fragmented_packet_count"], 1)
        self.assertAlmostEqual(state["ttl_mean"], 63.333333333333336)
        self.assertAlmostEqual(state["packet_iat_mean_ms"], 100.0)
        self.assertEqual(state["packet_unique_dst_ports"], 1)

        states = build_packet_state_windows(
            events, 1.0, 1.3, window_seconds=0.1, stride_seconds=0.1
        )
        self.assertEqual(len(states), 3)
        self.assertEqual([item["packet_event_count"] for item in states], [1, 1, 1])


if __name__ == "__main__":
    unittest.main()
