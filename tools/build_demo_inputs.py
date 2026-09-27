#!/usr/bin/env python3
"""Create harmless offline PCAP/CSV inputs for the competition file uploader.

Nothing is transmitted. Scapy packets are serialized directly to disk and the
CSV contains equivalent synthetic flow metadata. The timeline is intentionally
benign-like first, followed by sequential destination-port probes so packet and
flow feature extraction can be demonstrated without a network connection.
"""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scapy.all import Ether, IP, Raw, TCP, wrpcap  # type: ignore[import-untyped]


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    output = ROOT / "samples"
    output.mkdir(parents=True, exist_ok=True)
    pcap = output / "aegisnet_demo_recon.pcap"
    flow_csv = output / "aegisnet_demo_flows.csv"
    packets = []
    rows = []
    epoch = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # 30 seconds of ordinary HTTPS-like exchanges.
    for second in range(30):
        stamp = epoch + timedelta(seconds=second)
        packet = (
            Ether()
            / IP(src="10.1.10.10", dst="10.20.10.10", ttl=64)
            / TCP(sport=41000 + second, dport=443, flags="PA", seq=1000 + second, window=8192)
            / Raw(b"demo")
        )
        packet.time = stamp.timestamp()
        packets.append(packet)
        rows.append({
            "Timestamp": stamp.isoformat(), "Src IP": "10.1.10.10", "Dst IP": "10.20.10.10",
            "Src Port": 41000 + second, "Dst Port": 443, "Protocol": 6,
            "Tot Fwd Pkts": 2, "Tot Bwd Pkts": 2, "TotLen Fwd Pkts": 180,
            "TotLen Bwd Pkts": 220, "ACK Flag Cnt": 1, "PSH Flag Cnt": 1,
        })

    # 40 seconds of sequential-port reconnaissance-like metadata.
    for index in range(80):
        stamp = epoch + timedelta(seconds=30 + index * 0.5)
        port = 20 + (index % 61)
        packet = (
            Ether()
            / IP(src="10.1.10.10", dst="10.20.10.10", ttl=63 - (index % 2))
            / TCP(sport=50000 + index, dport=port, flags="S", seq=5000 + index, window=4096)
        )
        packet.time = stamp.timestamp()
        packets.append(packet)
        rows.append({
            "Timestamp": stamp.isoformat(), "Src IP": "10.1.10.10", "Dst IP": "10.20.10.10",
            "Src Port": 50000 + index, "Dst Port": port, "Protocol": 6,
            "Tot Fwd Pkts": 1, "Tot Bwd Pkts": 0, "TotLen Fwd Pkts": 60,
            "TotLen Bwd Pkts": 0, "SYN Flag Cnt": 1, "ACK Flag Cnt": 0,
        })

    wrpcap(str(pcap), packets)
    fields = [
        "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol",
        "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts",
        "SYN Flag Cnt", "ACK Flag Cnt", "PSH Flag Cnt",
    ]
    with flow_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    print(f"PCAP: {pcap} ({pcap.stat().st_size} bytes)")
    print(f"CSV:  {flow_csv} ({flow_csv.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
