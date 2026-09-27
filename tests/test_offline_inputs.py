from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd
from scapy.all import Ether, IP, Raw, TCP, wrpcap  # type: ignore[import-untyped]


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
from offline_inputs import build_offline_states, read_flow_csv  # noqa: E402


class OfflineInputTests(unittest.TestCase):
    def test_generic_flow_csv_is_normalised(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "flows.csv"
            pd.DataFrame(
                [
                    {
                        "Timestamp": "2026-01-01T00:00:01Z",
                        "Src IP": "10.1.1.1",
                        "Dst IP": "10.2.2.2",
                        "Src Port": 1234,
                        "Dst Port": 80,
                        "Protocol": 6,
                        "Tot Fwd Pkts": 3,
                        "Tot Bwd Pkts": 2,
                        "TotLen Fwd Pkts": 300,
                        "TotLen Bwd Pkts": 200,
                        "SYN Flag Cnt": 1,
                    },
                    {
                        "Timestamp": "2026-01-01T00:00:11Z",
                        "Src IP": "10.1.1.1",
                        "Dst IP": "10.2.2.2",
                        "Src Port": 1234,
                        "Dst Port": 81,
                        "Protocol": 6,
                        "Tot Fwd Pkts": 2,
                        "Tot Bwd Pkts": 1,
                        "TotLen Fwd Pkts": 200,
                        "TotLen Bwd Pkts": 100,
                        "SYN Flag Cnt": 1,
                    },
                ]
            ).to_csv(path, index=False)
            records, _ = read_flow_csv(path)
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["packets"], 5)
            self.assertEqual(records[0]["bytes"], 500)
            states, state_meta = build_offline_states(path)
            self.assertGreaterEqual(len(states), 2)
            self.assertEqual(state_meta["input_type"], "csv")
            self.assertEqual(states[0]["packet_capture_present"], 0)

    def test_pcap_builds_flow_and_packet_state(self) -> None:
        packets = []
        for index, port in enumerate((20, 21, 22, 23)):
            packet = (
                Ether()
                / IP(src="10.1.1.1", dst="10.2.2.2", ttl=64 - index)
                / TCP(sport=40000, dport=port, flags="S", seq=100 + index, window=4096)
                / Raw(b"x")
            )
            packet.time = 1.0 + index * 0.1
            packets.append(packet)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "traffic.pcap"
            wrpcap(str(path), packets)
            states, meta = build_offline_states(path)
            self.assertEqual(meta["input_type"], "pcap")
            self.assertEqual(states[0]["packet_capture_present"], 1)
            self.assertEqual(states[0]["packet_event_count"], 4)
            self.assertGreaterEqual(states[0]["unique_dst_ports"], 4)


if __name__ == "__main__":
    unittest.main()
