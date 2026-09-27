#!/usr/bin/env python3
"""Extract packet-level world-model features from a PCAP/PCAPNG file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from packet_state import aggregate_packet_state, build_packet_state_windows, read_pcap_events


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--window-seconds", type=float)
    parser.add_argument("--stride-seconds", type=float)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    events = read_pcap_events(args.pcap)
    features = aggregate_packet_state(events)
    document = {
        "source": str(args.pcap),
        "packet_events": len(events),
        "features": features,
    }
    if args.window_seconds and events:
        stride = args.stride_seconds or args.window_seconds
        document["states"] = build_packet_state_windows(
            events,
            events[0]["timestamp"],
            events[-1]["timestamp"] + 1e-9,
            window_seconds=args.window_seconds,
            stride_seconds=stride,
        )
    body = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
