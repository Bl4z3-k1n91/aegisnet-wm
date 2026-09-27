#!/usr/bin/env python3
"""Small RFC3164-style UDP syslog collector for the air-gapped lab."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path


PRI_RE = re.compile(r"^<(\d{1,3})>(.*)$", re.DOTALL)


def parse_message(payload: bytes, exporter: str) -> dict[str, object]:
    text = payload.decode("utf-8", errors="replace").strip("\x00\r\n ")
    priority = None
    match = PRI_RE.match(text)
    if match:
        priority = int(match.group(1))
        text = match.group(2).strip()
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "exporter": exporter,
        "priority": priority,
        "facility": None if priority is None else priority // 8,
        "severity": None if priority is None else priority % 8,
        "message": text,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--jsonl", type=Path, default=Path("outputs/syslog.jsonl"))
    args = parser.parse_args()

    args.jsonl.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.bind, args.port))
        print(f"Listening for syslog on {args.bind}:{args.port}")
        with args.jsonl.open("a", encoding="utf-8") as output:
            while True:
                payload, address = sock.recvfrom(65535)
                record = parse_message(payload, address[0])
                line = json.dumps(record, sort_keys=True)
                output.write(line + "\n")
                output.flush()
                print(line)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"syslog collector error: {exc}", file=sys.stderr)
        return 1
    finally:
        sock.close()


if __name__ == "__main__":
    raise SystemExit(main())
