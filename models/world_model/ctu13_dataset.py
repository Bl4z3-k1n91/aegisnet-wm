from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from config import CLASS_TO_ID, INFILTRATION_CLASSES, VICTIM_TO_ID, WorldModelConfig

ROOT = Path(__file__).resolve().parents[2]
FLOW_FEATURES = [
    'flow_count','packet_count','byte_count','unique_src_ips','unique_dst_ips','unique_dst_ports',
    'new_dst_hosts','new_dst_ports','tcp_flow_count','syn_count','ack_count','rst_count','fin_count',
    'psh_count','urg_count','syn_only_count','syn_ack_ratio','rst_ratio','max_host_fanout',
    'max_port_fanout','port_entropy','sequential_port_score','east_west_flows','north_south_flows',
    'iat_mean_ms','iat_std_ms','iat_cv','flow_duration_mean_ms','flow_duration_p95_ms'
]


def scenario_id(path: Path) -> int:
    match = re.search(r'scenario-(\d+)-', path.name)
    if match is None:
        match = re.match(r'^(\d+)\.binetflow$', path.name, flags=re.IGNORECASE)
    if not match:
        raise ValueError(f'cannot infer scenario id from {path.name}')
    return int(match.group(1))


def canonical_label(value: Any) -> str:
    text = str(value or '')
    # CTU documentation explicitly says only From-Botnet flows are malicious.
    if 'From-Botnet' in text:
        return 'C2_BEACON_PATTERN'
    return 'BENIGN'


def _flag_present(state: str, letter: str) -> bool:
    return letter in str(state or '').upper()


def aggregate_scenario(path: Path, window_seconds: int, chunksize: int = 250_000) -> pd.DataFrame:
    buckets: dict[pd.Timestamp, dict[str, Any]] = {}
    usecols = ['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport','State','TotPkts','TotBytes','SrcBytes','Label']
    for chunk in pd.read_csv(path, chunksize=chunksize, usecols=usecols, low_memory=False):
        ts = pd.to_datetime(chunk['StartTime'], errors='coerce', utc=True)
        valid = ts.notna()
        chunk = chunk.loc[valid].copy()
        ts = ts.loc[valid]
        if chunk.empty:
            continue
        chunk['_ts'] = ts
        chunk['_bucket'] = ts.dt.floor(f'{window_seconds}s')
        chunk['_label'] = chunk['Label'].map(canonical_label)
        chunk['_dur_ms'] = pd.to_numeric(chunk['Dur'], errors='coerce').fillna(0.0) * 1000.0
        chunk['_pkts'] = pd.to_numeric(chunk['TotPkts'], errors='coerce').fillna(0.0)
        chunk['_bytes'] = pd.to_numeric(chunk['TotBytes'], errors='coerce').fillna(0.0)
        chunk['_port'] = pd.to_numeric(chunk['Dport'], errors='coerce').fillna(0).astype(int)
        chunk['_proto'] = chunk['Proto'].astype(str).str.lower()
        chunk['_state'] = chunk['State'].fillna('').astype(str)
        chunk['_src'] = chunk['SrcAddr'].astype(str)
        chunk['_dst'] = chunk['DstAddr'].astype(str)
        for bucket, group in chunk.groupby('_bucket', sort=False):
            slot = buckets.setdefault(bucket, {
                'flow_count':0,'packet_count':0.0,'byte_count':0.0,'src':set(),'dst':set(),'ports':Counter(),
                'tcp_flow_count':0,'syn_count':0,'ack_count':0,'rst_count':0,'fin_count':0,'psh_count':0,'urg_count':0,
                'syn_only_count':0,'src_dsts':defaultdict(set),'src_ports':defaultdict(set),'east_west_flows':0,
                'north_south_flows':0,'times':[],'durations':[],'attack_flows':0,
            })
            slot['flow_count'] += int(len(group))
            slot['packet_count'] += float(group['_pkts'].sum())
            slot['byte_count'] += float(group['_bytes'].sum())
            slot['src'].update(group['_src'].tolist()); slot['dst'].update(group['_dst'].tolist())
            positive_ports = group.loc[group['_port'] > 0, '_port'].astype(int).tolist()
            slot['ports'].update(positive_ports)
            slot['times'].extend((group['_ts'].astype('int64') / 1e6).astype(float).tolist())
            slot['durations'].extend(group['_dur_ms'].astype(float).tolist())
            for row in group[['_src','_dst','_port','_proto','_state','_label']].itertuples(index=False, name=None):
                src,dst,port,proto,state,label = row
                if proto == 'tcp': slot['tcp_flow_count'] += 1
                s=_flag_present(state,'S'); a=_flag_present(state,'A'); rr=_flag_present(state,'R'); f=_flag_present(state,'F'); p=_flag_present(state,'P'); u=_flag_present(state,'U')
                slot['syn_count'] += int(s); slot['ack_count'] += int(a); slot['rst_count'] += int(rr); slot['fin_count'] += int(f); slot['psh_count'] += int(p); slot['urg_count'] += int(u)
                slot['syn_only_count'] += int(s and not a)
                slot['src_dsts'][src].add(dst)
                if int(port) > 0: slot['src_ports'][src].add(int(port))
                internal = str(src).startswith('147.32.') and str(dst).startswith('147.32.')
                slot['east_west_flows'] += int(internal); slot['north_south_flows'] += int(not internal)
                slot['attack_flows'] += int(label != 'BENIGN')
    records=[]
    for bucket in sorted(buckets):
        s=buckets[bucket]
        port_total=sum(s['ports'].values())
        if port_total:
            probs=np.asarray(list(s['ports'].values()),dtype=float)/port_total
            entropy=float(-(probs*np.log2(probs)).sum())
        else: entropy=0.0
        sorted_ports=sorted(s['ports'])
        sequential=(sum((b-a)==1 for a,b in zip(sorted_ports,sorted_ports[1:]))/(len(sorted_ports)-1)) if len(sorted_ports)>1 else 0.0
        times=np.sort(np.asarray(s['times'],dtype=float))
        iats=np.diff(times) if len(times)>1 else np.asarray([],dtype=float)
        iat_mean=float(iats.mean()) if len(iats) else 0.0
        iat_std=float(iats.std()) if len(iats) else 0.0
        durations=np.asarray(s['durations'],dtype=float)
        records.append({
            'window_start':bucket.isoformat(), 'label':'C2_BEACON_PATTERN' if s['attack_flows'] else 'BENIGN',
            'flow_count':float(s['flow_count']),'packet_count':s['packet_count'],'byte_count':s['byte_count'],
            'unique_src_ips':float(len(s['src'])),'unique_dst_ips':float(len(s['dst'])),'unique_dst_ports':float(len(s['ports'])),
            'new_dst_hosts':0.0,'new_dst_ports':0.0,'tcp_flow_count':float(s['tcp_flow_count']),
            'syn_count':float(s['syn_count']),'ack_count':float(s['ack_count']),'rst_count':float(s['rst_count']),'fin_count':float(s['fin_count']),
            'psh_count':float(s['psh_count']),'urg_count':float(s['urg_count']),'syn_only_count':float(s['syn_only_count']),
            'syn_ack_ratio':float(s['syn_count']/max(s['ack_count'],1)),'rst_ratio':float(s['rst_count']/max(s['flow_count'],1)),
            'max_host_fanout':float(max((len(v) for v in s['src_dsts'].values()),default=0)),
            'max_port_fanout':float(max((len(v) for v in s['src_ports'].values()),default=0)),
            'port_entropy':entropy,'sequential_port_score':float(sequential),'east_west_flows':float(s['east_west_flows']),
            'north_south_flows':float(s['north_south_flows']),'iat_mean_ms':iat_mean,'iat_std_ms':iat_std,
            'iat_cv':float(iat_std/max(iat_mean,1e-6)) if iat_mean else 0.0,
            'flow_duration_mean_ms':float(durations.mean()) if len(durations) else 0.0,
            'flow_duration_p95_ms':float(np.percentile(durations,95)) if len(durations) else 0.0,
            '_dst_set':set(s['dst']),'_port_set':set(s['ports']),
        })
    result=pd.DataFrame(records).sort_values('window_start').reset_index(drop=True)
    for i in range(len(result)):
        prior_hosts=set(); prior_ports=set()
        for j in range(max(0,i-6),i):
            prior_hosts.update(result.at[j,'_dst_set']); prior_ports.update(result.at[j,'_port_set'])
        result.at[i,'new_dst_hosts']=float(len(result.at[i,'_dst_set']-prior_hosts))
        result.at[i,'new_dst_ports']=float(len(result.at[i,'_port_set']-prior_ports))
    return result.drop(columns=['_dst_set','_port_set'])


def sequences(frame: pd.DataFrame, config: WorldModelConfig, prefix: str) -> dict[str,np.ndarray]:
    total=config.history_steps+max(config.horizons)
    if len(frame)<total: return {}
    values=frame[FLOW_FEATURES].astype(float).fillna(0).to_numpy(np.float32)
    labels=frame['label'].tolist(); ts=pd.to_datetime(frame['window_start'],utc=True)
    out={k:[] for k in ('x','future_state','future_label','attack','change','onset','infiltration','victim','current_label','campaign_id')}
    for start in range(len(frame)-total+1):
        stop=start+total; hist_end=start+config.history_steps
        deltas=ts.iloc[start:stop].diff().dropna().dt.total_seconds().to_numpy()
        if len(deltas) and not np.allclose(deltas,config.window_seconds,atol=.001): continue
        current=labels[hist_end-1]
        out['x'].append(values[start:hist_end]); out['current_label'].append(CLASS_TO_ID[current]); out['campaign_id'].append(f'{prefix}-{start:08d}')
        fs=[]; fl=[]; attack=[]; change=[]; onset=[]; infil=[]; victim=[]
        for h in config.horizons:
            pos=hist_end-1+h; lab=labels[pos]
            fs.append(values[pos]); fl.append(CLASS_TO_ID[lab]); attack.append(float(lab!='BENIGN')); change.append(float(lab!=current)); onset.append(float(current=='BENIGN' and lab!='BENIGN')); infil.append(float(lab in INFILTRATION_CLASSES)); victim.append(VICTIM_TO_ID['NONE' if lab=='BENIGN' else 'MULTI'])
        out['future_state'].append(fs); out['future_label'].append(fl); out['attack'].append(attack); out['change'].append(change); out['onset'].append(onset); out['infiltration'].append(infil); out['victim'].append(victim)
    if not out['x']: return {}
    return {'x':np.asarray(out['x'],np.float32),'future_state':np.asarray(out['future_state'],np.float32),'future_label':np.asarray(out['future_label'],np.int64),'attack':np.asarray(out['attack'],np.float32),'change':np.asarray(out['change'],np.float32),'onset':np.asarray(out['onset'],np.float32),'infiltration':np.asarray(out['infiltration'],np.float32),'victim':np.asarray(out['victim'],np.int64),'current_label':np.asarray(out['current_label'],np.int64),'campaign_id':np.asarray(out['campaign_id'],dtype='U64')}


def main()->int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('input',type=Path); p.add_argument('--output',type=Path,default=ROOT/'dataset'/'releases'/'ctu13-temporal-v1'); p.add_argument('--window-seconds',type=int,default=10); args=p.parse_args()
    files=sorted(args.input.glob('*.binetflow'),key=scenario_id)
    if not files: raise SystemExit('no CTU-13 scenario binetflow files found')
    config=WorldModelConfig(window_seconds=args.window_seconds)
    by_split={'train':[],'val':[],'test':[]}; summary={}
    for path in files:
        sid=scenario_id(path); split='train' if sid<=50 else ('val' if sid<=52 else 'test')
        print(f'aggregating scenario {sid}: {path.name}',flush=True)
        frame=aggregate_scenario(path,config.window_seconds); seq=sequences(frame,config,f'scenario-{sid}')
        attack_windows=int((frame['label']!='BENIGN').sum()) if not frame.empty else 0
        summary[str(sid)]={'split':split,'windows':int(len(frame)),'attack_windows':attack_windows,'sequences':int(len(seq.get('x',[])))}
        if seq: by_split[split].append(seq)
    args.output.mkdir(parents=True,exist_ok=True); split_summary={}
    for split,pieces in by_split.items():
        if not pieces: continue
        merged={k:np.concatenate([p[k] for p in pieces],axis=0) for k in pieces[0]}; np.savez_compressed(args.output/f'{split}.npz',**merged)
        split_summary[split]={'sequences':int(len(merged['x'])),'scenarios':sorted({int(str(x).split('-')[1]) for x in merged['campaign_id'].tolist()})}
    manifest={'release':args.output.name,'evidence_status':'real_public_dataset','source':'CTU-13 bidirectional labelled NetFlows','features':FLOW_FEATURES,'history_steps':config.history_steps,'window_seconds':config.window_seconds,'horizons_steps':list(config.horizons),'horizons_seconds':[h*config.window_seconds for h in config.horizons],'split_strategy':'scenario-level split: 42-50 train, 51-52 validation, 53-54 test','label_mapping_note':'Only CTU From-Botnet flows are treated as malicious per dataset documentation; mapped operationally to C2_BEACON_PATTERN. To-Botnet is not marked malicious.','victim_supervision':'generic only: NONE for benign, MULTI for attack; CTU hosts are not mapped into the EVE topology','scenarios':summary,'splits':split_summary}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8'); print(json.dumps(manifest,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
