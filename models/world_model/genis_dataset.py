from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'features'))

from state_vector import FLOW_FEATURES  # noqa: E402
from config import (  # noqa: E402
    CLASS_TO_ID,
    INFILTRATION_CLASSES,
    VICTIM_TO_ID,
    WorldModelConfig,
)


DEFAULT_ZIP = ROOT / 'dataset' / 'public' / 'genis' / '3-scenarios.zip'
DEFAULT_OUTPUT = ROOT / 'dataset' / 'releases' / 'genis-temporal-v1'

# Whole-scenario split: no temporal window from one scenario can cross splits.
SPLIT_SCENARIOS = {
    'train': (1, 2, 3, 6),
    'val': (4, 7),
    'test': (5, 8),
}

STAGE_ORDER = {
    'BENIGN': 0,
    'RECONNAISSANCE': 1,
    'INITIAL_ACCESS_PATTERN': 2,
    'DDOS_HIGH': 3,
}


def canonical_category(value: Any) -> str | None:
    text = str(value or '').strip().lower()
    if text == 'benign':
        return 'BENIGN'
    if text == 'recon':
        return 'RECONNAISSANCE'
    if text == 'bruteforce':
        return 'INITIAL_ACCESS_PATTERN'
    if text == 'dos':
        return 'DDOS_HIGH'
    return None


def seconds_of_day(series: pd.Series) -> pd.Series:
    parts = series.astype(str).str.split(':', expand=True)
    if parts.shape[1] < 3:
        return pd.Series(np.nan, index=series.index, dtype=float)
    return (
        pd.to_numeric(parts[0], errors='coerce') * 3600.0
        + pd.to_numeric(parts[1], errors='coerce') * 60.0
        + pd.to_numeric(parts[2], errors='coerce')
    )


def numeric(series: pd.Series) -> pd.Series:
    return (
        pd.to_numeric(series, errors='coerce')
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
    )


def internal_address(value: str) -> bool:
    text = str(value)
    return text.startswith('192.168.') or text.startswith('10.') or text.startswith('172.16.')


@dataclass
class BinAccumulator:
    flow_count: int = 0
    packet_count: float = 0.0
    byte_count: float = 0.0
    srcs: set[str] = field(default_factory=set)
    dsts: set[str] = field(default_factory=set)
    ports: Counter[int] = field(default_factory=Counter)
    src_dsts: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    src_ports: dict[str, set[int]] = field(default_factory=lambda: defaultdict(set))
    tcp_flow_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    east_west_flows: int = 0
    north_south_flows: int = 0
    iat_values_ms: list[float] = field(default_factory=list)
    durations_ms: list[float] = field(default_factory=list)
    malicious_labels: Counter[str] = field(default_factory=Counter)


def update_bins(
    buckets: dict[int, BinAccumulator],
    chunk: pd.DataFrame,
    window_seconds: int,
) -> None:
    seconds = seconds_of_day(chunk['StartTime'])
    valid = seconds.notna()
    if not valid.any():
        return
    chunk = chunk.loc[valid].copy()
    seconds = seconds.loc[valid]

    chunk['_bin'] = (seconds // window_seconds * window_seconds).astype(int)
    chunk['_packets'] = numeric(chunk['TotPkts'])
    chunk['_bytes'] = numeric(chunk['TotBytes'])
    # Argus/GeNIS Dur is seconds; Aegis flow-duration features are milliseconds.
    chunk['_duration_ms'] = numeric(chunk['Dur']) * 1000.0
    chunk['_dport'] = pd.to_numeric(chunk['Dport'], errors='coerce')
    # GeNIS documentation explicitly defines SIntPkt/DIntPkt as milliseconds.
    chunk['_siat_ms'] = numeric(chunk['SIntPkt'])
    chunk['_diat_ms'] = numeric(chunk['DIntPkt'])
    chunk['_mapped_label'] = chunk['CategoryLabel'].map(canonical_category)

    for bin_id, group in chunk.groupby('_bin', sort=False):
        slot = buckets.setdefault(int(bin_id), BinAccumulator())
        slot.flow_count += int(len(group))
        slot.packet_count += float(group['_packets'].sum())
        slot.byte_count += float(group['_bytes'].sum())

        srcs = group['SrcAddr'].astype(str)
        dsts = group['DstAddr'].astype(str)
        slot.srcs.update(srcs.tolist())
        slot.dsts.update(dsts.tolist())

        ports = group['_dport'].dropna().astype(int)
        positive_ports = ports[ports > 0]
        slot.ports.update(positive_ports.tolist())

        proto = group['Proto'].astype(str).str.lower()
        slot.tcp_flow_count += int((proto == 'tcp').sum())

        # GeNIS exposes Argus transaction State, not raw TCP flag bitmaps.
        # Only exact RST/FIN transaction states are mapped conservatively.
        state = group['State'].fillna('').astype(str).str.upper()
        slot.rst_count += int((state == 'RST').sum())
        slot.fin_count += int((state == 'FIN').sum())

        for src, dst, port in zip(srcs, dsts, group['_dport']):
            slot.src_dsts[src].add(dst)
            if pd.notna(port) and int(port) > 0:
                slot.src_ports[src].add(int(port))
            if internal_address(src) and internal_address(dst):
                slot.east_west_flows += 1
            else:
                slot.north_south_flows += 1

        for column in ('_siat_ms', '_diat_ms'):
            values = group.loc[group[column] > 0, column].astype(float).to_numpy()
            if len(values):
                slot.iat_values_ms.extend(values.tolist())

        durations = group.loc[group['_duration_ms'] >= 0, '_duration_ms'].astype(float).to_numpy()
        if len(durations):
            slot.durations_ms.extend(durations.tolist())

        malicious = group.loc[group['BinaryLabel'] == 1, '_mapped_label'].dropna()
        if len(malicious):
            slot.malicious_labels.update(malicious.astype(str).tolist())


def counter_entropy(counter: Counter[int]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    probabilities = np.asarray(list(counter.values()), dtype=float) / float(total)
    return float(-(probabilities * np.log2(probabilities)).sum())


def sequential_port_score(ports: set[int]) -> float:
    values = sorted(ports)
    if len(values) < 2:
        return 0.0
    sequential = sum((right - left) == 1 for left, right in zip(values, values[1:]))
    return float(sequential / (len(values) - 1))


def bin_label(slot: BinAccumulator) -> str:
    if not slot.malicious_labels:
        return 'BENIGN'
    # If stages overlap in one 10-second bin, keep the furthest-progressed stage.
    return max(slot.malicious_labels, key=lambda label: STAGE_ORDER.get(label, -1))


def bins_to_frame(
    buckets: dict[int, BinAccumulator],
    window_seconds: int,
) -> pd.DataFrame:
    if not buckets:
        return pd.DataFrame()

    records: list[dict[str, Any]] = []
    previous_hosts: deque[set[str]] = deque(maxlen=6)
    previous_ports: deque[set[int]] = deque(maxlen=6)

    first_bin = min(buckets)
    last_bin = max(buckets)
    for bin_id in range(first_bin, last_bin + 1, window_seconds):
        slot = buckets.get(bin_id, BinAccumulator())
        known_hosts = set().union(*previous_hosts) if previous_hosts else set()
        known_ports = set().union(*previous_ports) if previous_ports else set()
        current_hosts = set(slot.dsts)
        current_ports = set(slot.ports)

        iats = np.asarray(slot.iat_values_ms, dtype=float)
        durations = np.asarray(slot.durations_ms, dtype=float)
        iat_mean = float(iats.mean()) if len(iats) else 0.0
        iat_std = float(iats.std()) if len(iats) else 0.0

        records.append(
            {
                'window_start_sec': int(bin_id),
                'label': bin_label(slot),
                'flow_count': float(slot.flow_count),
                'packet_count': float(slot.packet_count),
                'byte_count': float(slot.byte_count),
                'unique_src_ips': float(len(slot.srcs)),
                'unique_dst_ips': float(len(slot.dsts)),
                'unique_dst_ports': float(len(current_ports)),
                'new_dst_hosts': float(len(current_hosts - known_hosts)),
                'new_dst_ports': float(len(current_ports - known_ports)),
                'tcp_flow_count': float(slot.tcp_flow_count),
                # Raw SYN/ACK/PSH/URG flag counters are unavailable in GeNIS.
                'syn_count': 0.0,
                'ack_count': 0.0,
                'rst_count': float(slot.rst_count),
                'fin_count': float(slot.fin_count),
                'psh_count': 0.0,
                'urg_count': 0.0,
                'syn_only_count': 0.0,
                'syn_ack_ratio': 0.0,
                'rst_ratio': float(slot.rst_count / max(slot.flow_count, 1)),
                'max_host_fanout': float(
                    max((len(destinations) for destinations in slot.src_dsts.values()), default=0)
                ),
                'max_port_fanout': float(
                    max((len(ports) for ports in slot.src_ports.values()), default=0)
                ),
                'port_entropy': counter_entropy(slot.ports),
                'sequential_port_score': sequential_port_score(current_ports),
                'east_west_flows': float(slot.east_west_flows),
                'north_south_flows': float(slot.north_south_flows),
                'iat_mean_ms': iat_mean,
                'iat_std_ms': iat_std,
                'iat_cv': float(iat_std / max(iat_mean, 1e-6)) if iat_mean else 0.0,
                'flow_duration_mean_ms': float(durations.mean()) if len(durations) else 0.0,
                'flow_duration_p95_ms': float(np.percentile(durations, 95)) if len(durations) else 0.0,
            }
        )

        previous_hosts.append(current_hosts)
        previous_ports.append(current_ports)

    return pd.DataFrame(records)


def aggregate_scenario(
    archive: ZipFile,
    member: str,
    window_seconds: int,
    chunksize: int = 50_000,
) -> pd.DataFrame:
    buckets: dict[int, BinAccumulator] = {}
    usecols = [
        'StartTime',
        'Dur',
        'SrcAddr',
        'DstAddr',
        'Proto',
        'Dport',
        'TotPkts',
        'TotBytes',
        'SIntPkt',
        'DIntPkt',
        'State',
        'BinaryLabel',
        'CategoryLabel',
    ]
    with archive.open(member) as stream:
        for chunk in pd.read_csv(stream, usecols=usecols, chunksize=chunksize, low_memory=False):
            update_bins(buckets, chunk, window_seconds)
    return bins_to_frame(buckets, window_seconds)


def make_sequences(
    frame: pd.DataFrame,
    scenario_id: int,
    config: WorldModelConfig,
) -> dict[str, np.ndarray]:
    total_steps = config.history_steps + max(config.horizons)
    if len(frame) < total_steps:
        return {}

    values = frame[list(FLOW_FEATURES)].astype(float).fillna(0.0).to_numpy(dtype=np.float32)
    labels = frame['label'].astype(str).tolist()
    starts = frame['window_start_sec'].astype(int).to_numpy()

    output: dict[str, list[Any]] = {
        key: []
        for key in (
            'x',
            'future_state',
            'future_label',
            'attack',
            'change',
            'onset',
            'infiltration',
            'victim',
            'current_label',
            'campaign_id',
        )
    }

    expected_offsets = np.arange(total_steps, dtype=int) * config.window_seconds
    for start in range(len(frame) - total_steps + 1):
        stop = start + total_steps
        segment_starts = starts[start:stop]
        if not np.array_equal(segment_starts - segment_starts[0], expected_offsets):
            continue

        history_end = start + config.history_steps
        current = labels[history_end - 1]
        output['x'].append(values[start:history_end])
        output['current_label'].append(CLASS_TO_ID[current])
        output['campaign_id'].append(f'genis-s{scenario_id}-w{start:05d}')

        future_states: list[np.ndarray] = []
        future_labels: list[int] = []
        attack: list[float] = []
        change: list[float] = []
        onset: list[float] = []
        infiltration: list[float] = []
        victims: list[int] = []

        for horizon in config.horizons:
            position = history_end - 1 + horizon
            label = labels[position]
            future_states.append(values[position])
            future_labels.append(CLASS_TO_ID[label])
            attack.append(float(label != 'BENIGN'))
            change.append(float(label != current))
            onset.append(float(current == 'BENIGN' and label != 'BENIGN'))
            infiltration.append(float(label in INFILTRATION_CLASSES))
            victims.append(VICTIM_TO_ID['NONE' if label == 'BENIGN' else 'MULTI'])

        output['future_state'].append(future_states)
        output['future_label'].append(future_labels)
        output['attack'].append(attack)
        output['change'].append(change)
        output['onset'].append(onset)
        output['infiltration'].append(infiltration)
        output['victim'].append(victims)

    if not output['x']:
        return {}

    return {
        'x': np.asarray(output['x'], dtype=np.float32),
        'future_state': np.asarray(output['future_state'], dtype=np.float32),
        'future_label': np.asarray(output['future_label'], dtype=np.int64),
        'attack': np.asarray(output['attack'], dtype=np.float32),
        'change': np.asarray(output['change'], dtype=np.float32),
        'onset': np.asarray(output['onset'], dtype=np.float32),
        'infiltration': np.asarray(output['infiltration'], dtype=np.float32),
        'victim': np.asarray(output['victim'], dtype=np.int64),
        'current_label': np.asarray(output['current_label'], dtype=np.int64),
        'campaign_id': np.asarray(output['campaign_id'], dtype='U48'),
    }


def scenario_id_from_member(member: str) -> int:
    stem = Path(member).stem
    # scenario-1-disrupt -> 1
    return int(stem.split('-')[1])


def split_for_scenario(scenario_id: int) -> str:
    for split, scenarios in SPLIT_SCENARIOS.items():
        if scenario_id in scenarios:
            return split
    raise ValueError(f'scenario {scenario_id} not assigned to a split')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, default=DEFAULT_ZIP)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--window-seconds', type=int, default=10)
    args = parser.parse_args()

    config = WorldModelConfig(window_seconds=args.window_seconds)
    args.output.mkdir(parents=True, exist_ok=True)
    windows_dir = args.output / 'scenario_windows'
    windows_dir.mkdir(exist_ok=True)

    pieces: dict[str, list[dict[str, np.ndarray]]] = {split: [] for split in SPLIT_SCENARIOS}
    scenario_summary: dict[str, Any] = {}

    with ZipFile(args.zip) as archive:
        members = sorted(
            (
                info.filename
                for info in archive.infolist()
                if info.filename.startswith('3-scenarios/scenarios-10-sec/scenario-')
                and info.filename.endswith('.csv')
            ),
            key=scenario_id_from_member,
        )

        for member in members:
            scenario_id = scenario_id_from_member(member)
            split = split_for_scenario(scenario_id)
            print(f'aggregating GeNIS scenario {scenario_id} -> {split}', flush=True)
            frame = aggregate_scenario(archive, member, config.window_seconds)
            frame.to_csv(windows_dir / f'scenario-{scenario_id}.csv', index=False)
            sequence_data = make_sequences(frame, scenario_id, config)
            if sequence_data:
                pieces[split].append(sequence_data)

            counts = Counter(frame['label'].astype(str).tolist()) if not frame.empty else Counter()
            scenario_summary[str(scenario_id)] = {
                'split': split,
                'windows': int(len(frame)),
                'sequences': int(len(sequence_data.get('x', []))),
                'class_windows': dict(counts),
                'first_window_sec': int(frame['window_start_sec'].iloc[0]) if not frame.empty else None,
                'last_window_sec': int(frame['window_start_sec'].iloc[-1]) if not frame.empty else None,
            }
            print(
                f"  windows={len(frame)} sequences={len(sequence_data.get('x', []))} labels={dict(counts)}",
                flush=True,
            )

    split_summary: dict[str, Any] = {}
    train_future_ids: set[int] = set()
    for split, split_pieces in pieces.items():
        if not split_pieces:
            raise RuntimeError(f'no sequences generated for split {split}')
        merged = {
            key: np.concatenate([piece[key] for piece in split_pieces], axis=0)
            for key in split_pieces[0]
        }
        np.savez_compressed(args.output / f'{split}.npz', **merged)
        future = merged['future_label'].reshape(-1)
        unique_future = sorted(set(int(value) for value in future.tolist()))
        if split == 'train':
            train_future_ids = set(unique_future)
        split_summary[split] = {
            'sequences': int(len(merged['x'])),
            'scenarios': list(SPLIT_SCENARIOS[split]),
            'future_class_ids': unique_future,
            'future_class_counts': {
                label: int(np.sum(future == class_id))
                for label, class_id in CLASS_TO_ID.items()
                if np.any(future == class_id)
            },
            'attack_targets': int(merged['attack'].sum()),
            'change_targets': int(merged['change'].sum()),
            'onset_targets': int(merged['onset'].sum()),
        }

    test_ids = set(split_summary['test']['future_class_ids'])
    unseen_test_ids = sorted(test_ids - train_future_ids)
    id_to_class = {value: key for key, value in CLASS_TO_ID.items()}

    manifest = {
        'release': args.output.name,
        'evidence_status': 'real_public_dataset',
        'source': 'GeNIS (GECAD Network Intrusion Scenarios), Zenodo record 14919237, scenarios-10-sec',
        'source_archive': str(args.zip),
        'features': list(FLOW_FEATURES),
        'feature_count': len(FLOW_FEATURES),
        'history_steps': config.history_steps,
        'window_seconds': config.window_seconds,
        'history_seconds': config.history_steps * config.window_seconds,
        'horizons_steps': list(config.horizons),
        'horizons_seconds': [horizon * config.window_seconds for horizon in config.horizons],
        'split_strategy': 'whole-scenario split: train 1,2,3,6; validation 4,7; test 5,8',
        'class_mapping': {
            'benign': 'BENIGN',
            'recon': 'RECONNAISSANCE',
            'bruteforce': 'INITIAL_ACCESS_PATTERN',
            'dos': 'DDOS_HIGH',
        },
        'victim_supervision': 'generic only: NONE for benign, MULTI for attack; GeNIS assets are not mapped to the EVE topology',
        'feature_mapping': {
            'direct_or_derived': [
                'flow_count', 'packet_count', 'byte_count', 'unique_src_ips', 'unique_dst_ips',
                'unique_dst_ports', 'new_dst_hosts', 'new_dst_ports', 'tcp_flow_count', 'rst_count',
                'fin_count', 'rst_ratio', 'max_host_fanout', 'max_port_fanout', 'port_entropy',
                'sequential_port_score', 'east_west_flows', 'north_south_flows', 'iat_mean_ms',
                'iat_std_ms', 'iat_cv', 'flow_duration_mean_ms', 'flow_duration_p95_ms',
            ],
            'unavailable_set_zero': [
                'syn_count', 'ack_count', 'psh_count', 'urg_count', 'syn_only_count', 'syn_ack_ratio',
            ],
            'notes': [
                'GeNIS SIntPkt/DIntPkt are documented as milliseconds.',
                'GeNIS Dur is converted from seconds to milliseconds.',
                'Argus transaction State is not treated as a raw TCP flag bitmap; only exact RST/FIN states are mapped.',
            ],
        },
        'unseen_test_classes': [id_to_class[class_id] for class_id in unseen_test_ids],
        'scenarios': scenario_summary,
        'splits': split_summary,
    }
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
