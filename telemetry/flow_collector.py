#!/usr/bin/env python3
"""Dependency-free NetFlow v9 and IPFIX collector for the local EVE lab."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import socket
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterable


CSV_FIELDS = [
    "timestamp",
    "export_time",
    "exporter",
    "version",
    "observation_domain",
    "sequence",
    "sequence_delta",
    "template_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "tcp_flags",
    "dscp",
    "input_if",
    "output_if",
    "direction",
    "next_hop",
    "application_engine",
    "application_selector",
    "application",
    "bytes",
    "packets",
    "flow_start",
    "flow_end",
]

ENGINE_LAYER = {1: "L3", 3: "L4", 13: "L7"}


@dataclass(frozen=True)
class Field:
    element_id: int
    length: int
    enterprise: int | None = None


@dataclass
class Template:
    fields: list[Field]

    @property
    def minimum_length(self) -> int:
        return sum(1 if field.length == 65535 else field.length for field in self.fields)


class NbarTable:
    def __init__(self, path: Path | None) -> None:
        self.names: dict[tuple[str, int], str] = {}
        if path and path.exists():
            pattern = re.compile(r"^(\S+)\s+(\d+)\s+(L3|L4|L7)\b")
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                match = pattern.match(raw.strip())
                if match:
                    name, selector, layer = match.groups()
                    self.names.setdefault((layer, int(selector)), name)

    def lookup(self, engine: int, selector: int) -> str:
        layer = ENGINE_LAYER.get(engine)
        if layer and (layer, selector) in self.names:
            return self.names[(layer, selector)]
        return "unknown"


class FlowParser:
    def __init__(self, nbar: NbarTable | None = None) -> None:
        self.templates: dict[tuple[int, str, int, int], Template] = {}
        self.sequences: dict[tuple[int, str, int], int] = {}
        self.nbar = nbar or NbarTable(None)

    def parse_packet(self, data: bytes, exporter: str) -> list[dict[str, object]]:
        if len(data) < 2:
            return []
        version = struct.unpack_from("!H", data)[0]
        if version == 9:
            return self._parse_v9(data, exporter)
        if version == 10:
            return self._parse_ipfix(data, exporter)
        return []

    def _parse_v9(self, data: bytes, exporter: str) -> list[dict[str, object]]:
        if len(data) < 20:
            return []
        version, _count, uptime, export_time, sequence, domain = struct.unpack_from(
            "!HHIIII", data
        )
        return self._parse_sets(
            data,
            20,
            len(data),
            version,
            exporter,
            domain,
            sequence,
            export_time,
            uptime,
            template_set_id=0,
            options_set_id=1,
        )

    def _parse_ipfix(self, data: bytes, exporter: str) -> list[dict[str, object]]:
        if len(data) < 16:
            return []
        version, message_length, export_time, sequence, domain = struct.unpack_from(
            "!HHIII", data
        )
        if message_length < 16 or message_length > len(data):
            return []
        return self._parse_sets(
            data,
            16,
            message_length,
            version,
            exporter,
            domain,
            sequence,
            export_time,
            None,
            template_set_id=2,
            options_set_id=3,
        )

    def _parse_sets(
        self,
        data: bytes,
        offset: int,
        limit: int,
        version: int,
        exporter: str,
        domain: int,
        sequence: int,
        export_time: int,
        system_uptime_ms: int | None,
        *,
        template_set_id: int,
        options_set_id: int,
    ) -> list[dict[str, object]]:
        records: list[dict[str, object]] = []
        sequence_key = (version, exporter, domain)
        previous = self.sequences.get(sequence_key)
        sequence_delta = "" if previous is None else max(0, sequence - previous)
        self.sequences[sequence_key] = sequence
        while offset + 4 <= limit:
            set_id, set_length = struct.unpack_from("!HH", data, offset)
            if set_length < 4 or offset + set_length > limit:
                break
            payload = data[offset + 4 : offset + set_length]
            if set_id == template_set_id:
                self._parse_templates(payload, version, exporter, domain)
            elif set_id == options_set_id:
                pass
            elif set_id >= 256:
                records.extend(
                    self._parse_data_set(
                        set_id,
                        payload,
                        version,
                        exporter,
                        domain,
                        sequence,
                        sequence_delta,
                        export_time,
                        system_uptime_ms,
                    )
                )
            offset += set_length
        return records

    def _parse_templates(
        self,
        payload: bytes,
        version: int,
        exporter: str,
        domain: int,
    ) -> None:
        offset = 0
        while offset + 4 <= len(payload):
            template_id, field_count = struct.unpack_from("!HH", payload, offset)
            offset += 4
            key = (version, exporter, domain, template_id)
            if template_id < 256:
                break
            if field_count == 0:
                self.templates.pop(key, None)
                continue
            fields: list[Field] = []
            valid = True
            for _ in range(field_count):
                if offset + 4 > len(payload):
                    valid = False
                    break
                raw_id, length = struct.unpack_from("!HH", payload, offset)
                offset += 4
                enterprise = None
                element_id = raw_id
                if version == 10 and raw_id & 0x8000:
                    element_id = raw_id & 0x7FFF
                    if offset + 4 > len(payload):
                        valid = False
                        break
                    enterprise = struct.unpack_from("!I", payload, offset)[0]
                    offset += 4
                fields.append(Field(element_id, length, enterprise))
            if not valid:
                break
            self.templates[key] = Template(fields)

    def _parse_data_set(
        self,
        template_id: int,
        payload: bytes,
        version: int,
        exporter: str,
        domain: int,
        sequence: int,
        sequence_delta: int | str,
        export_time: int,
        system_uptime_ms: int | None,
    ) -> list[dict[str, object]]:
        template = self.templates.get((version, exporter, domain, template_id))
        if not template:
            return []
        records: list[dict[str, object]] = []
        offset = 0
        while len(payload) - offset >= template.minimum_length:
            values: list[tuple[Field, bytes]] = []
            start = offset
            valid = True
            for field in template.fields:
                length = field.length
                if length == 65535:
                    if offset >= len(payload):
                        valid = False
                        break
                    length = payload[offset]
                    offset += 1
                    if length == 255:
                        if offset + 2 > len(payload):
                            valid = False
                            break
                        length = struct.unpack_from("!H", payload, offset)[0]
                        offset += 2
                if offset + length > len(payload):
                    valid = False
                    break
                values.append((field, payload[offset : offset + length]))
                offset += length
            if not valid or offset == start:
                break
            record = self._decode_record(values)
            received_at = datetime.now(timezone.utc)
            flow_start = None
            flow_end = None
            if system_uptime_ms is not None:
                start_uptime = record.get("flow_start_uptime_ms")
                end_uptime = record.get("flow_end_uptime_ms")
                if isinstance(start_uptime, int) and start_uptime <= system_uptime_ms:
                    flow_start = (
                        received_at
                        - timedelta(milliseconds=system_uptime_ms - start_uptime)
                    ).isoformat()
                if isinstance(end_uptime, int) and end_uptime <= system_uptime_ms:
                    flow_end = (
                        received_at
                        - timedelta(milliseconds=system_uptime_ms - end_uptime)
                    ).isoformat()
            record.update(
                {
                    "timestamp": received_at.isoformat(),
                    "export_time": datetime.fromtimestamp(
                        export_time, timezone.utc
                    ).isoformat(),
                    "system_uptime_ms": system_uptime_ms,
                    "flow_start": flow_start,
                    "flow_end": flow_end,
                    "exporter": exporter,
                    "version": version,
                    "observation_domain": domain,
                    "sequence": sequence,
                    "sequence_delta": sequence_delta,
                    "template_id": template_id,
                }
            )
            records.append(record)
        return records

    def _decode_record(self, values: Iterable[tuple[Field, bytes]]) -> dict[str, object]:
        record: dict[str, object] = {}
        for field, raw in values:
            element = field.element_id
            number = int.from_bytes(raw, "big") if raw else 0
            if element == 1:
                record["bytes"] = number
            elif element == 2:
                record["packets"] = number
            elif element == 4:
                record["protocol"] = number
            elif element == 5:
                record["dscp"] = number >> 2
            elif element == 6:
                record["tcp_flags"] = number
            elif element == 7:
                record["src_port"] = number
            elif element == 8 and len(raw) == 4:
                record["src_ip"] = str(ipaddress.IPv4Address(raw))
            elif element == 10:
                record["input_if"] = number
            elif element == 11:
                record["dst_port"] = number
            elif element == 12 and len(raw) == 4:
                record["dst_ip"] = str(ipaddress.IPv4Address(raw))
            elif element == 14:
                record["output_if"] = number
            elif element == 15 and len(raw) == 4:
                record["next_hop"] = str(ipaddress.IPv4Address(raw))
            elif element == 27 and len(raw) == 16:
                record["src_ip"] = str(ipaddress.IPv6Address(raw))
            elif element == 28 and len(raw) == 16:
                record["dst_ip"] = str(ipaddress.IPv6Address(raw))
            elif element == 61:
                record["direction"] = number
            elif element == 95 and raw:
                engine = raw[0]
                selector = int.from_bytes(raw[1:], "big")
                record["application_engine"] = engine
                record["application_selector"] = selector
                record["application"] = self.nbar.lookup(engine, selector)
            elif element in {150, 152}:
                divisor = 1 if element == 150 else 1000
                record["flow_start"] = datetime.fromtimestamp(
                    number / divisor, timezone.utc
                ).isoformat()
            elif element in {151, 153}:
                divisor = 1 if element == 151 else 1000
                record["flow_end"] = datetime.fromtimestamp(
                    number / divisor, timezone.utc
                ).isoformat()
            elif element == 22:
                record["flow_start_uptime_ms"] = number
            elif element == 21:
                record["flow_end_uptime_ms"] = number
        return record


class RecordWriter:
    def __init__(self, csv_path: Path, jsonl_path: Path | None) -> None:
        self.csv_path = csv_path
        self.jsonl_path = jsonl_path
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        self.csv_file = csv_path.open("a", encoding="utf-8", newline="")
        self.csv_writer = csv.DictWriter(
            self.csv_file, fieldnames=CSV_FIELDS, extrasaction="ignore"
        )
        if csv_path.stat().st_size == 0:
            self.csv_writer.writeheader()
        self.jsonl_file = (
            jsonl_path.open("a", encoding="utf-8") if jsonl_path is not None else None
        )

    def write(self, records: Iterable[dict[str, object]]) -> None:
        for record in records:
            self.csv_writer.writerow(record)
            if self.jsonl_file:
                self.jsonl_file.write(json.dumps(record, sort_keys=True) + "\n")
        self.csv_file.flush()
        if self.jsonl_file:
            self.jsonl_file.flush()

    def close(self) -> None:
        self.csv_file.close()
        if self.jsonl_file:
            self.jsonl_file.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2055)
    parser.add_argument("--csv", type=Path, default=Path("outputs/flows.csv"))
    parser.add_argument("--jsonl", type=Path)
    parser.add_argument("--nbar-table", type=Path)
    args = parser.parse_args()

    flow_parser = FlowParser(NbarTable(args.nbar_table))
    writer = RecordWriter(args.csv, args.jsonl)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.bind, args.port))
        print(f"Listening for NetFlow v9/IPFIX on {args.bind}:{args.port}")
        while True:
            packet, address = sock.recvfrom(65535)
            records = flow_parser.parse_packet(packet, address[0])
            if records:
                writer.write(records)
                for record in records:
                    print(json.dumps(record, sort_keys=True))
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"collector error: {exc}", file=sys.stderr)
        return 1
    finally:
        sock.close()
        writer.close()


if __name__ == "__main__":
    raise SystemExit(main())
