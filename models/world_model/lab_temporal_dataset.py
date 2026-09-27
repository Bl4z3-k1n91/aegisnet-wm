from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'features'))
from state_vector import FLOW_FEATURES, PACKET_FEATURES, MODEL_FEATURES, build_state_vector
from config import CLASS_TO_ID, HORIZONS, INFILTRATION_CLASSES, VICTIM_BY_CLASS, VICTIM_TO_ID, WorldModelConfig

LABEL_ALIASES = {
    'STATE_0': 'BENIGN', 'BENIGN': 'BENIGN',
    'STATE_1': 'RECONNAISSANCE', 'RECONNAISSANCE': 'RECONNAISSANCE',
    'STATE_2': 'INITIAL_ACCESS_PATTERN', 'INITIAL_ACCESS_PATTERN': 'INITIAL_ACCESS_PATTERN',
    'STATE_3': 'LATERAL_MOVEMENT', 'LATERAL_MOVEMENT': 'LATERAL_MOVEMENT',
    'STATE_4': 'C2_BEACON_PATTERN', 'C2_BEACON_PATTERN': 'C2_BEACON_PATTERN',
    'STATE_5': 'EXFILTRATION_LIKE', 'STATE_X': 'EXFILTRATION_LIKE', 'EXFILTRATION_LIKE': 'EXFILTRATION_LIKE',
    'STATE_V1': 'DDOS_LOW', 'DDOS_LOW': 'DDOS_LOW',
    'STATE_V2': 'DDOS_MEDIUM', 'DDOS_MEDIUM': 'DDOS_MEDIUM',
    'STATE_V3': 'DDOS_HIGH', 'DDOS_HIGH': 'DDOS_HIGH',
    'STATE_R': 'BENIGN', 'RECOVERY': 'BENIGN',
}


def canonical(value: Any) -> str | None:
    return LABEL_ALIASES.get(str(value or '').strip().upper())


def feature_names(mode: str) -> list[str]:
    if mode == 'flow': return list(FLOW_FEATURES)
    if mode == 'flow-packet': return list(FLOW_FEATURES + PACKET_FEATURES)
    if mode == 'full': return list(MODEL_FEATURES)
    raise ValueError(mode)


def label_at(phases: list[sqlite3.Row], moment: datetime) -> str | None:
    for phase in phases:
        start = datetime.fromisoformat(str(phase['started_at'])); end = datetime.fromisoformat(str(phase['ended_at']))
        if start <= moment <= end:
            return canonical(phase['label'])
    return None


def run_states(
    connection: sqlite3.Connection,
    run: sqlite3.Row,
    features: list[str],
    config: WorldModelConfig,
) -> tuple[list[np.ndarray], list[str], list[str]]:
    phases = connection.execute(
        'SELECT id,label,started_at,ended_at FROM scenario_phases WHERE run_id=? AND ended_at IS NOT NULL ORDER BY started_at',
        (run['id'],),
    ).fetchall()
    if not phases: return [], [], []
    cursor = datetime.fromisoformat(str(phases[0]['started_at']))
    end = datetime.fromisoformat(str(phases[-1]['ended_at']))
    states=[]; labels=[]; sample_times=[]
    while cursor + timedelta(seconds=config.window_seconds) <= end:
        window_end = cursor + timedelta(seconds=config.window_seconds)
        label = label_at(phases, window_end - timedelta(microseconds=1))
        if label is not None:
            state = build_state_vector(connection, cursor, window_end, lookback_seconds=60)
            states.append(np.asarray([float(state.get(name) or 0.0) for name in features], dtype=np.float32))
            labels.append(label)
            sample_times.append(window_end.isoformat())
        cursor = window_end
    return states, labels, sample_times


def windows(
    states: list[np.ndarray],
    labels: list[str],
    sample_times: list[str],
    run_id: int,
    config: WorldModelConfig,
    *,
    scenario: str = 'unknown',
    campaign_id: str | None = None,
) -> dict[str, np.ndarray] | None:
    total=config.history_steps+max(config.horizons)
    if len(states)<total: return None
    out={k:[] for k in (
        'x','future_state','future_label','attack','change','onset','infiltration','victim',
        'current_label','campaign_id','source_campaign_id','run_id','scenario','sample_time','next_stage'
    )}
    for start in range(len(states)-total+1):
        h_end=start+config.history_steps
        current_label = labels[h_end-1]
        out['x'].append(states[start:h_end]); out['current_label'].append(CLASS_TO_ID[current_label])
        # ``campaign_id`` is the split-group identity consumed by existing
        # leakage checks.  It must be unique per complete run because one
        # collection campaign can intentionally contain train/val/test runs.
        out['campaign_id'].append(f'run-{run_id}')
        out['source_campaign_id'].append(campaign_id or f'run-{run_id}')
        out['run_id'].append(run_id)
        out['scenario'].append(scenario)
        out['sample_time'].append(sample_times[h_end-1])
        next_stage = current_label
        for future_label in labels[h_end:h_end + max(config.horizons)]:
            if future_label != current_label:
                next_stage = future_label
                break
        out['next_stage'].append(CLASS_TO_ID[next_stage])
        fs=[]; fl=[]; attack=[]; change=[]; onset=[]; inf=[]; vic=[]
        for h in config.horizons:
            pos=h_end-1+h; lab=labels[pos]
            fs.append(states[pos]); fl.append(CLASS_TO_ID[lab]); attack.append(float(lab!='BENIGN')); change.append(float(lab!=labels[h_end-1])); onset.append(float(labels[h_end-1]=='BENIGN' and lab!='BENIGN')); inf.append(float(lab in INFILTRATION_CLASSES)); vic.append(VICTIM_TO_ID[VICTIM_BY_CLASS[lab]])
        out['future_state'].append(fs); out['future_label'].append(fl); out['attack'].append(attack); out['change'].append(change); out['onset'].append(onset); out['infiltration'].append(inf); out['victim'].append(vic)
    return {
        'x':np.asarray(out['x'],np.float32),'future_state':np.asarray(out['future_state'],np.float32),
        'future_label':np.asarray(out['future_label'],np.int64),'attack':np.asarray(out['attack'],np.float32),'change':np.asarray(out['change'],np.float32),'infiltration':np.asarray(out['infiltration'],np.float32),
        'onset':np.asarray(out['onset'],np.float32),
        'victim':np.asarray(out['victim'],np.int64),'current_label':np.asarray(out['current_label'],np.int64),
        'next_stage':np.asarray(out['next_stage'],np.int64),
        'campaign_id':np.asarray(out['campaign_id'],dtype='U96'),
        'source_campaign_id':np.asarray(out['source_campaign_id'],dtype='U96'),
        'run_id':np.asarray(out['run_id'],np.int64),
        'scenario':np.asarray(out['scenario'],dtype='U64'),
        'sample_time':np.asarray(out['sample_time'],dtype='U40')}


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,default=ROOT/'outputs'/'telemetry.db')
    parser.add_argument('--output',type=Path,default=ROOT/'dataset'/'releases'/'ntro-lab-temporal-v1')
    parser.add_argument('--feature-mode',choices=('flow','flow-packet','full'),default='flow')
    parser.add_argument('--campaign-id',help='Optional exact scenario_runs.campaign_id filter.')
    args=parser.parse_args(); config=WorldModelConfig(); features=feature_names(args.feature_mode)
    c=sqlite3.connect(f'file:{args.database.as_posix()}?mode=ro',uri=True); c.row_factory=sqlite3.Row
    try:
        query="SELECT id,COALESCE(split,'train') split,status,scenario,campaign_id FROM scenario_runs WHERE status IN ('COMPLETED','TRAFFIC_ONLY')"
        params:list[Any]=[]
        if args.campaign_id:
            query += ' AND campaign_id=?'
            params.append(args.campaign_id)
        query += ' ORDER BY id'
        runs=c.execute(query,params).fetchall()
        by_split={'train':[],'val':[],'test':[]}
        for run in runs:
            states,labels,sample_times=run_states(c,run,features,config)
            seq=windows(
                states,labels,sample_times,int(run['id']),config,
                scenario=str(run['scenario'] or 'unknown'),
                campaign_id=str(run['campaign_id']) if run['campaign_id'] else None,
            )
            if not seq: continue
            raw=str(run['split'] or 'train').lower(); split='val' if raw in {'validation','val'} else ('test' if raw=='test' else 'train')
            by_split[split].append(seq)
    finally:c.close()
    args.output.mkdir(parents=True,exist_ok=True); summary={}
    for split,pieces in by_split.items():
        if not pieces: continue
        merged={key:np.concatenate([piece[key] for piece in pieces],axis=0) for key in pieces[0]}
        np.savez_compressed(args.output/f'{split}.npz',**merged); summary[split]={'sequences':len(merged['x']),'campaigns':len(set(merged['campaign_id'].tolist()))}
    manifest={
        'release':args.output.name,
        'evidence_status':'real_lab_temporal',
        'feature_mode':args.feature_mode,
        'features':features,
        'feature_count':len(features),
        'history_steps':config.history_steps,
        'window_seconds':config.window_seconds,
        'horizons_steps':list(config.horizons),
        'horizons_seconds':[h*config.window_seconds for h in config.horizons],
        'split_strategy':'run-level split from scenario_runs.split',
        'campaign_filter':args.campaign_id,
        'ground_truth':'exact scenario_phases boundaries; sample_time is the history-end timestamp',
        'splits':summary,
    }
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8'); print(json.dumps(manifest,indent=2)); return 0

if __name__=='__main__': raise SystemExit(main())
