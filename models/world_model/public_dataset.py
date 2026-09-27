from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from config import CLASS_TO_ID, HORIZONS, INFILTRATION_CLASSES, VICTIM_TO_ID, WorldModelConfig

ROOT = Path(__file__).resolve().parents[2]
DAY_ORDER = ('monday', 'tuesday', 'wednesday', 'thursday', 'friday')
DAY_OF_MONTH = {
    'monday': 3,
    'tuesday': 4,
    'wednesday': 5,
    'thursday': 6,
    'friday': 7,
}


def day_name(path: Path) -> str:
    lower = path.name.lower()
    for day in DAY_ORDER:
        if day in lower:
            return day
    return 'unknown'


def norm(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '', str(name).lower())


def find_column(columns: list[str], *candidates: str) -> str | None:
    lookup = {norm(column): column for column in columns}
    for candidate in candidates:
        if norm(candidate) in lookup:
            return lookup[norm(candidate)]
    return None


def canonical_label(value: Any) -> str | None:
    text = str(value).strip().lower().replace('–', '-').replace('—', '-')
    if text in {'', 'nan', 'none', 'null'}:
        return None
    if text in {'benign', 'normal'}:
        return 'BENIGN'
    if 'portscan' in text or 'scan' in text or 'probe' in text:
        return 'RECONNAISSANCE'
    if 'bot' in text:
        return 'C2_BEACON_PATTERN'
    if 'infiltration' in text:
        return 'LATERAL_MOVEMENT'
    if 'ddos' in text or text.startswith('dos ') or 'slowloris' in text or 'slowhttptest' in text or 'hulk' in text or 'goldeneye' in text:
        return 'DDOS_HIGH'
    if 'patator' in text or 'brute' in text or 'web attack' in text or 'sql injection' in text or 'xss' in text or 'heartbleed' in text:
        return 'INITIAL_ACCESS_PATTERN'
    return None


def parse_timestamp(series: pd.Series) -> pd.Series:
    parsed = pd.to_datetime(series, errors='coerce', utc=True, dayfirst=True)
    if parsed.notna().mean() < 0.5:
        parsed = pd.to_datetime(series, errors='coerce', utc=True)
    return parsed


def numeric(frame: pd.DataFrame, column: str | None, default: float = 0.0) -> pd.Series:
    if column is None:
        return pd.Series(np.full(len(frame), default), index=frame.index, dtype=float)
    return pd.to_numeric(frame[column], errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(default)


def aggregate_file(path: Path, window_seconds: int = 10) -> pd.DataFrame:
    if path.suffix.lower() == '.parquet':
        raw = pd.read_parquet(path)
    else:
        raw = pd.read_csv(path, low_memory=False, encoding='cp1252')
    raw.columns = [str(column).strip() for column in raw.columns]
    cols = list(raw.columns)
    timestamp_col = find_column(cols, 'Timestamp', 'stime')
    label_col = find_column(cols, 'Label', 'attack_cat', 'label')
    if timestamp_col is None or label_col is None:
        raise ValueError(
            f'{path.name}: timestamp or label column not found. '
            'Use GeneratedLabelledFlows CSVs for temporal forecasting; '
            'the MachineLearningCSV release may omit chronology columns.'
        )
    timestamp = parse_timestamp(raw[timestamp_col])
    source_day = day_name(path)
    if source_day in DAY_OF_MONTH:
        expected_day = DAY_OF_MONTH[source_day]
        timestamp = timestamp.map(
            lambda value: (
                value.replace(year=2017, month=7, day=expected_day)
                if pd.notna(value)
                else value
            )
        )
    valid = timestamp.notna()
    raw = raw.loc[valid].copy()
    timestamp = timestamp.loc[valid]
    if raw.empty:
        return pd.DataFrame()

    src_col = find_column(cols, 'Source IP', 'Src IP', 'srcip')
    dst_col = find_column(cols, 'Destination IP', 'Dst IP', 'dstip')
    dst_port_col = find_column(cols, 'Destination Port', 'Dst Port', 'dport')
    protocol_col = find_column(cols, 'Protocol', 'proto')
    duration_col = find_column(cols, 'Flow Duration', 'dur')
    fwd_packets = find_column(cols, 'Total Fwd Packets', 'spkts')
    bwd_packets = find_column(cols, 'Total Backward Packets', 'dpkts')
    fwd_bytes = find_column(cols, 'Total Length of Fwd Packets', 'sbytes')
    bwd_bytes = find_column(cols, 'Total Length of Bwd Packets', 'dbytes')
    syn_col = find_column(cols, 'SYN Flag Count', 'syn')
    ack_col = find_column(cols, 'ACK Flag Count', 'ack')
    rst_col = find_column(cols, 'RST Flag Count', 'rst')
    fin_col = find_column(cols, 'FIN Flag Count', 'fin')
    psh_col = find_column(cols, 'PSH Flag Count')
    urg_col = find_column(cols, 'URG Flag Count')
    iat_mean_col = find_column(cols, 'Flow IAT Mean', 'sinpkt')
    iat_std_col = find_column(cols, 'Flow IAT Std')

    work = pd.DataFrame(index=raw.index)
    work['timestamp'] = timestamp
    work['bucket'] = timestamp.dt.floor(f'{window_seconds}s')
    work['label'] = raw[label_col].map(canonical_label)
    work = work.loc[work['label'].notna()].copy()
    if work.empty:
        return pd.DataFrame()
    work['src'] = raw[src_col].astype(str) if src_col else 'unknown'
    work['dst'] = raw[dst_col].astype(str) if dst_col else 'unknown'
    work['dst_port'] = numeric(raw, dst_port_col)
    work['protocol'] = raw[protocol_col].astype(str).str.lower() if protocol_col else ''
    work['duration'] = numeric(raw, duration_col)
    work['fwd_packets'] = numeric(raw, fwd_packets)
    work['bwd_packets'] = numeric(raw, bwd_packets)
    work['fwd_bytes'] = numeric(raw, fwd_bytes)
    work['bwd_bytes'] = numeric(raw, bwd_bytes)
    for name, column in [('syn', syn_col), ('ack', ack_col), ('rst', rst_col), ('fin', fin_col), ('psh', psh_col), ('urg', urg_col)]:
        work[name] = numeric(raw, column)
    work['iat_mean'] = numeric(raw, iat_mean_col)
    work['iat_std'] = numeric(raw, iat_std_col)
    if iat_mean_col and 'flowiat' in norm(iat_mean_col):
        work['iat_mean'] = work['iat_mean'] / 1000.0
    if iat_std_col and 'flowiat' in norm(iat_std_col):
        work['iat_std'] = work['iat_std'] / 1000.0

    records = []
    for bucket, group in work.groupby('bucket', sort=True):
        packets = float((group['fwd_packets'] + group['bwd_packets']).sum())
        bytes_total = float((group['fwd_bytes'] + group['bwd_bytes']).sum())
        ports = group.loc[group['dst_port'] > 0, 'dst_port'].astype(int)
        port_counts = Counter(ports.tolist())
        total_ports = sum(port_counts.values())
        entropy = 0.0
        if total_ports:
            probs = np.asarray(list(port_counts.values()), dtype=float) / total_ports
            entropy = float(-(probs * np.log2(probs)).sum())
        sorted_ports = sorted(set(ports.tolist()))
        sequential = 0.0
        if len(sorted_ports) > 1:
            sequential = sum(b - a == 1 for a, b in zip(sorted_ports, sorted_ports[1:])) / (len(sorted_ports) - 1)
        tcp = group['protocol'].str.contains('tcp|6', regex=True, na=False)
        syn = float(group['syn'].sum()); ack = float(group['ack'].sum()); rst = float(group['rst'].sum())
        attack_labels = group.loc[group['label'] != 'BENIGN', 'label']
        dominant = (
            attack_labels.value_counts().index[0]
            if not attack_labels.empty
            else 'BENIGN'
        )
        src_values = set(group['src'].astype(str))
        dst_values = set(group['dst'].astype(str))
        internal_src = group['src'].astype(str).str.startswith('192.168.10.')
        internal_dst = group['dst'].astype(str).str.startswith('192.168.10.')
        east_west = int((internal_src & internal_dst).sum())
        records.append({
            'window_start': bucket.isoformat(),
            'label': dominant,
            'flow_count': float(len(group)),
            'packet_count': packets,
            'byte_count': bytes_total,
            'unique_src_ips': float(group['src'].nunique()),
            'unique_dst_ips': float(group['dst'].nunique()),
            'unique_dst_ports': float(ports.nunique()),
            'new_dst_hosts': 0.0,
            'new_dst_ports': 0.0,
            'tcp_flow_count': float(tcp.sum()),
            'syn_count': syn,
            'ack_count': ack,
            'rst_count': rst,
            'fin_count': float(group['fin'].sum()),
            'psh_count': float(group['psh'].sum()),
            'urg_count': float(group['urg'].sum()),
            'syn_only_count': float(max(syn - ack, 0.0)),
            'syn_ack_ratio': float(syn / max(ack, 1.0)),
            'rst_ratio': float(rst / max(len(group), 1)),
            'max_host_fanout': float(group.groupby('src')['dst'].nunique().max() if len(group) else 0),
            'max_port_fanout': float(group.groupby('src')['dst_port'].nunique().max() if len(group) else 0),
            'port_entropy': entropy,
            'sequential_port_score': sequential,
            'east_west_flows': float(east_west),
            'north_south_flows': float(len(group) - east_west),
            'iat_mean_ms': float(group['iat_mean'].mean()),
            'iat_std_ms': float(group['iat_std'].mean()),
            'iat_cv': float(group['iat_std'].mean() / max(group['iat_mean'].mean(), 1e-6)),
            'flow_duration_mean_ms': float(group['duration'].mean() / 1000.0),
            'flow_duration_p95_ms': float(np.percentile(group['duration'], 95) / 1000.0),
            '_dst_set': dst_values,
            '_port_set': set(ports.tolist()),
        })
    result = pd.DataFrame(records).sort_values('window_start').reset_index(drop=True)
    for index in range(len(result)):
        lookback_start = max(0, index - 6)
        previous_hosts: set[str] = set()
        previous_ports: set[int] = set()
        for previous in range(lookback_start, index):
            previous_hosts.update(result.at[previous, '_dst_set'])
            previous_ports.update(result.at[previous, '_port_set'])
        current_hosts = result.at[index, '_dst_set']
        current_ports = result.at[index, '_port_set']
        result.at[index, 'new_dst_hosts'] = float(len(current_hosts - previous_hosts))
        result.at[index, 'new_dst_ports'] = float(len(current_ports - previous_ports))
    return result.drop(columns=['_dst_set', '_port_set'])


def sequences_from_windows(
    frame: pd.DataFrame,
    features: list[str],
    config: WorldModelConfig,
    campaign_prefix: str,
) -> dict[str, np.ndarray]:
    max_h = max(config.horizons)
    total = config.history_steps + max_h
    if len(frame) < total:
        return {}
    arrays = {'x': [], 'future_state': [], 'future_label': [], 'attack': [], 'change': [], 'onset': [], 'infiltration': [], 'victim': [], 'current_label': [], 'campaign_id': []}
    values = frame[features].astype(float).fillna(0.0).to_numpy(np.float32)
    labels = frame['label'].astype(str).tolist()
    timestamps = pd.to_datetime(frame['window_start'], utc=True, errors='coerce')
    for start in range(0, len(frame) - total + 1):
        history_end = start + config.history_steps
        stop = start + total
        deltas = timestamps.iloc[start:stop].diff().dropna().dt.total_seconds().to_numpy()
        if len(deltas) and not np.allclose(deltas, float(config.window_seconds), atol=0.001):
            continue
        arrays['x'].append(values[start:history_end])
        current = labels[history_end - 1]
        arrays['current_label'].append(CLASS_TO_ID[current])
        arrays['campaign_id'].append(f"{campaign_prefix}-{start:08d}")
        future_states = []; future_labels = []; attack = []; change = []; onset = []; infiltration = []; victims = []
        for h in config.horizons:
            pos = history_end - 1 + h
            label = labels[pos]
            future_states.append(values[pos]); future_labels.append(CLASS_TO_ID[label])
            attack.append(float(label != 'BENIGN'))
            change.append(float(label != current))
            onset.append(float(current == 'BENIGN' and label != 'BENIGN'))
            infiltration.append(float(label in INFILTRATION_CLASSES))
            victims.append(VICTIM_TO_ID['NONE' if label == 'BENIGN' else 'MULTI'])
        arrays['future_state'].append(future_states); arrays['future_label'].append(future_labels); arrays['attack'].append(attack); arrays['change'].append(change); arrays['onset'].append(onset); arrays['infiltration'].append(infiltration); arrays['victim'].append(victims)
    if not arrays['x']:
        return {}
    return {
        'x': np.asarray(arrays['x'], dtype=np.float32),
        'future_state': np.asarray(arrays['future_state'], dtype=np.float32),
        'future_label': np.asarray(arrays['future_label'], dtype=np.int64),
        'attack': np.asarray(arrays['attack'], dtype=np.float32),
        'change': np.asarray(arrays['change'], dtype=np.float32),
        'onset': np.asarray(arrays['onset'], dtype=np.float32),
        'infiltration': np.asarray(arrays['infiltration'], dtype=np.float32),
        'victim': np.asarray(arrays['victim'], dtype=np.int64),
        'current_label': np.asarray(arrays['current_label'], dtype=np.int64),
        'campaign_id': np.asarray(arrays['campaign_id'], dtype='U32'),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='CIC-IDS-2017 CSV file or directory')
    parser.add_argument('--output', type=Path, default=ROOT / 'dataset' / 'releases' / 'cicids-temporal-v1')
    parser.add_argument(
        '--window-seconds',
        type=int,
        default=60,
        help='Temporal state width. CICIDS2017 labelled-flow CSVs are minute-resolution for most days.',
    )
    args = parser.parse_args()
    files = (
        sorted(list(args.input.glob('*.csv')) + list(args.input.glob('*.parquet')))
        if args.input.is_dir()
        else [args.input]
    )
    if not files:
        raise SystemExit('no CSV or Parquet files found')
    from json import loads
    clean_manifest = loads((ROOT / 'dataset' / 'releases' / 'ntro-clean-traffic-v1' / 'manifest.json').read_text(encoding='utf-8'))
    features = list(clean_manifest['features'])
    config = WorldModelConfig(window_seconds=args.window_seconds)
    args.output.mkdir(parents=True, exist_ok=True)
    file_frames = []
    for path in files:
        print(f'aggregating {path.name}', flush=True)
        current = aggregate_file(path, config.window_seconds)
        if not current.empty:
            current['source_file'] = path.name
            file_frames.append((path.name, current))
    if not file_frames:
        raise SystemExit('no usable windows generated')
    day_groups: dict[str, list[tuple[str, pd.DataFrame]]] = {}
    for filename, frame in file_frames:
        day_groups.setdefault(day_name(Path(filename)), []).append((filename, frame))
    if {'monday', 'tuesday', 'wednesday', 'thursday', 'friday'} <= set(day_groups):
        groups = {
            'train': day_groups['monday'] + day_groups['tuesday'] + day_groups['wednesday'],
            'val': day_groups['thursday'],
            'test': day_groups['friday'],
        }
        split_strategy = 'strict day-level split: Mon-Wed train, Thu validation, Fri test'
    else:
        n = len(file_frames)
        train_cut = max(1, int(n * 0.6))
        val_cut = max(train_cut + 1, int(n * 0.8)) if n >= 3 else train_cut
        groups = {
            'train': file_frames[:train_cut],
            'val': file_frames[train_cut:val_cut] or file_frames[:1],
            'test': file_frames[val_cut:] or file_frames[-1:],
        }
        split_strategy = 'file-level chronological split fallback'
    summary = {}
    for split, items in groups.items():
        pieces = []
        for filename, frame in items:
            seq = sequences_from_windows(frame, features, config, Path(filename).stem)
            if seq:
                pieces.append(seq)
        if not pieces:
            continue
        merged = {key: np.concatenate([piece[key] for piece in pieces], axis=0) for key in pieces[0]}
        np.savez_compressed(args.output / f'{split}.npz', **merged)
        future_labels = merged['future_label'].reshape(-1)
        class_counts = {
            label: int(np.sum(future_labels == class_id))
            for label, class_id in CLASS_TO_ID.items()
            if np.any(future_labels == class_id)
        }
        summary[split] = {
            'sequences': int(len(merged['x'])),
            'files': [name for name, _ in items],
            'days': sorted({day_name(Path(name)) for name, _ in items}),
            'future_class_counts': class_counts,
        }
    train_classes = set(summary.get('train', {}).get('future_class_counts', {}))
    test_classes = set(summary.get('test', {}).get('future_class_counts', {}))
    unseen_test_classes = sorted(test_classes - train_classes)
    manifest = {
        'release': args.output.name,
        'evidence_status': 'real_public_dataset',
        'source': 'CIC-IDS-2017-compatible CSV',
        'features': features,
        'history_steps': config.history_steps,
        'window_seconds': config.window_seconds,
        'horizons_steps': list(config.horizons),
        'horizons_seconds': [h * config.window_seconds for h in config.horizons],
        'split_strategy': split_strategy,
        'label_mapping_note': 'CIC labels are mapped to the AegisNet operational taxonomy; mapping is approximate for non-equivalent classes.',
        'victim_supervision': 'generic only: NONE for benign, MULTI for attack; CIC hosts are not mapped into the EVE topology',
        'unseen_test_classes': unseen_test_classes,
        'warning': (
            'Strict day-level CICIDS2017 splits can contain attack classes in Friday test that do not occur in Mon-Wed train. '
            'Treat multiclass results for those classes as zero-shot stress tests; binary onset/attack metrics remain interpretable.'
        ),
        'splits': summary,
    }
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
