from __future__ import annotations

import argparse, json, math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from config import CLASS_TO_ID, INFILTRATION_CLASSES, VICTIM_TO_ID, WorldModelConfig

ROOT=Path(__file__).resolve().parents[2]
FLOW_FEATURES=['flow_count','packet_count','byte_count','unique_src_ips','unique_dst_ips','unique_dst_ports','new_dst_hosts','new_dst_ports','tcp_flow_count','syn_count','ack_count','rst_count','fin_count','psh_count','urg_count','syn_only_count','syn_ack_ratio','rst_ratio','max_host_fanout','max_port_fanout','port_entropy','sequential_port_score','east_west_flows','north_south_flows','iat_mean_ms','iat_std_ms','iat_cv','flow_duration_mean_ms','flow_duration_p95_ms']


def class_label(category: Any, attack: int)->str:
    if int(attack)==0: return 'BENIGN'
    text=str(category or '').strip().lower()
    if 'recon' in text: return 'RECONNAISSANCE'
    if text=='dos': return 'DDOS_HIGH'
    return 'INITIAL_ACCESS_PATTERN'


def feature_names(root:Path)->list[str]:
    meta=pd.read_csv(root/'NUSW-NB15_features.csv',encoding='latin1')
    return meta['Name'].astype(str).str.strip().tolist()


def load_aggregate(root:Path,window_seconds:int)->dict[str,pd.DataFrame]:
    names=feature_names(root)
    use=['srcip','sport','dstip','dsport','proto','dur','sbytes','dbytes','Spkts','Dpkts','Stime','attack_cat','Label']
    by_day:dict[str,dict[int,dict[str,Any]]]={}
    for path in sorted(root.glob('UNSW-NB15_[1-4].csv')):
        print('reading',path.name,flush=True)
        for chunk in pd.read_csv(path,names=names,header=None,usecols=use,chunksize=200000,low_memory=False):
            st=pd.to_numeric(chunk['Stime'],errors='coerce')
            valid=st.notna(); chunk=chunk.loc[valid].copy(); st=st.loc[valid]
            chunk['_epoch']=st.astype(np.int64)
            chunk['_day']=pd.to_datetime(st,unit='s',utc=True).dt.date.astype(str)
            chunk['_bucket']=(chunk['_epoch']//window_seconds)*window_seconds
            chunk['_attack']=pd.to_numeric(chunk['Label'],errors='coerce').fillna(0).astype(int)
            chunk['_class']=[class_label(cat,a) for cat,a in zip(chunk['attack_cat'],chunk['_attack'])]
            chunk['_pkts']=pd.to_numeric(chunk['Spkts'],errors='coerce').fillna(0)+pd.to_numeric(chunk['Dpkts'],errors='coerce').fillna(0)
            chunk['_bytes']=pd.to_numeric(chunk['sbytes'],errors='coerce').fillna(0)+pd.to_numeric(chunk['dbytes'],errors='coerce').fillna(0)
            chunk['_durms']=pd.to_numeric(chunk['dur'],errors='coerce').fillna(0)*1000
            chunk['_port']=pd.to_numeric(chunk['dsport'],errors='coerce').fillna(0).astype(int)
            for (day,bucket),g in chunk.groupby(['_day','_bucket'],sort=False):
                daymap=by_day.setdefault(day,{})
                slot=daymap.setdefault(int(bucket),{'flows':0,'pkts':0.0,'bytes':0.0,'src':set(),'dst':set(),'ports':Counter(),'tcp':0,'src_dsts':defaultdict(set),'src_ports':defaultdict(set),'times':[],'dur':[],'attack':0,'classes':Counter()})
                slot['flows']+=len(g); slot['pkts']+=float(g['_pkts'].sum()); slot['bytes']+=float(g['_bytes'].sum())
                srcs=g['srcip'].astype(str); dsts=g['dstip'].astype(str); ports=g['_port'].astype(int)
                slot['src'].update(srcs.tolist()); slot['dst'].update(dsts.tolist()); slot['ports'].update(ports[ports>0].tolist())
                slot['tcp']+=int(g['proto'].astype(str).str.lower().eq('tcp').sum()); slot['times'].extend((g['_epoch'].astype(float)*1000).tolist()); slot['dur'].extend(g['_durms'].astype(float).tolist())
                slot['attack']+=int(g['_attack'].sum()); slot['classes'].update(g.loc[g['_attack']==1,'_class'].tolist())
                for src,dst,port in zip(srcs,dsts,ports):
                    slot['src_dsts'][src].add(dst)
                    if int(port)>0: slot['src_ports'][src].add(int(port))
    result={}
    for day,buckets in by_day.items():
        records=[]; all_buckets=range(min(buckets),max(buckets)+window_seconds,window_seconds)
        history_hosts=[]; history_ports=[]
        for bucket in all_buckets:
            s=buckets.get(bucket)
            if s is None:
                record={name:0.0 for name in FLOW_FEATURES}; record.update({'window_start':pd.to_datetime(bucket,unit='s',utc=True).isoformat(),'label':'BENIGN','attack':0.0}); current_hosts=set(); current_ports=set()
            else:
                total=sum(s['ports'].values())
                if total:
                    probs=np.asarray(list(s['ports'].values()),float)/total; entropy=float(-(probs*np.log2(probs)).sum())
                else: entropy=0.0
                ps=sorted(s['ports']); seq=sum((b-a)==1 for a,b in zip(ps,ps[1:]))/(len(ps)-1) if len(ps)>1 else 0.0
                times=np.sort(np.asarray(s['times'],float)); iats=np.diff(times) if len(times)>1 else np.asarray([],float); im=float(iats.mean()) if len(iats) else 0.; ist=float(iats.std()) if len(iats) else 0.
                dur=np.asarray(s['dur'],float); attack=int(s['attack']>0); label=s['classes'].most_common(1)[0][0] if s['classes'] else 'BENIGN'; current_hosts=set(s['dst']); current_ports=set(s['ports'])
                prev_hosts=set().union(*history_hosts[-6:]) if history_hosts else set(); prev_ports=set().union(*history_ports[-6:]) if history_ports else set()
                record={'window_start':pd.to_datetime(bucket,unit='s',utc=True).isoformat(),'label':label,'attack':float(attack),'flow_count':float(s['flows']),'packet_count':s['pkts'],'byte_count':s['bytes'],'unique_src_ips':float(len(s['src'])),'unique_dst_ips':float(len(s['dst'])),'unique_dst_ports':float(len(s['ports'])),'new_dst_hosts':float(len(current_hosts-prev_hosts)),'new_dst_ports':float(len(current_ports-prev_ports)),'tcp_flow_count':float(s['tcp']),'syn_count':0.,'ack_count':0.,'rst_count':0.,'fin_count':0.,'psh_count':0.,'urg_count':0.,'syn_only_count':0.,'syn_ack_ratio':0.,'rst_ratio':0.,'max_host_fanout':float(max((len(v) for v in s['src_dsts'].values()),default=0)),'max_port_fanout':float(max((len(v) for v in s['src_ports'].values()),default=0)),'port_entropy':entropy,'sequential_port_score':float(seq),'east_west_flows':0.,'north_south_flows':float(s['flows']),'iat_mean_ms':im,'iat_std_ms':ist,'iat_cv':float(ist/max(im,1e-6)) if im else 0.,'flow_duration_mean_ms':float(dur.mean()) if len(dur) else 0.,'flow_duration_p95_ms':float(np.percentile(dur,95)) if len(dur) else 0.}
            history_hosts.append(current_hosts); history_ports.append(current_ports); records.append(record)
        result[day]=pd.DataFrame(records)
    return result


def make_sequences(frame:pd.DataFrame,config:WorldModelConfig,prefix:str)->dict[str,np.ndarray]:
    total=config.history_steps+max(config.horizons); values=frame[FLOW_FEATURES].to_numpy(np.float32); labels=frame['label'].tolist(); attack_flags=frame['attack'].to_numpy(np.float32)
    out={k:[] for k in ('x','future_state','future_label','attack','change','onset','infiltration','victim','current_label','campaign_id')}
    for start in range(len(frame)-total+1):
        he=start+config.history_steps; current=labels[he-1]; current_attack=attack_flags[he-1]>0
        out['x'].append(values[start:he]); out['current_label'].append(CLASS_TO_ID[current]); out['campaign_id'].append(f'{prefix}-{start:07d}')
        fs=[]; fl=[]; att=[]; ch=[]; onset=[]; inf=[]; vic=[]
        for h in config.horizons:
            pos=he-1+h; lab=labels[pos]; a=bool(attack_flags[pos]>0)
            fs.append(values[pos]); fl.append(CLASS_TO_ID[lab]); att.append(float(a)); ch.append(float(lab!=current)); onset.append(float((not current_attack) and a)); inf.append(float(lab in INFILTRATION_CLASSES)); vic.append(VICTIM_TO_ID['NONE' if not a else 'MULTI'])
        out['future_state'].append(fs); out['future_label'].append(fl); out['attack'].append(att); out['change'].append(ch); out['onset'].append(onset); out['infiltration'].append(inf); out['victim'].append(vic)
    return {'x':np.asarray(out['x'],np.float32),'future_state':np.asarray(out['future_state'],np.float32),'future_label':np.asarray(out['future_label'],np.int64),'attack':np.asarray(out['attack'],np.float32),'change':np.asarray(out['change'],np.float32),'onset':np.asarray(out['onset'],np.float32),'infiltration':np.asarray(out['infiltration'],np.float32),'victim':np.asarray(out['victim'],np.int64),'current_label':np.asarray(out['current_label'],np.int64),'campaign_id':np.asarray(out['campaign_id'],dtype='U64')}


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('input',type=Path); p.add_argument('--output',type=Path,default=ROOT/'dataset'/'releases'/'unswnb15-temporal-v1'); p.add_argument('--window-seconds',type=int,default=10); args=p.parse_args(); config=WorldModelConfig(window_seconds=args.window_seconds)
    days=load_aggregate(args.input,args.window_seconds); ordered=sorted(days)
    if len(ordered)<3: raise SystemExit(f'need >=3 capture days, found {ordered}')
    split_day={'train':ordered[0],'val':ordered[1],'test':ordered[-1]}; args.output.mkdir(parents=True,exist_ok=True); summary={}
    for split,day in split_day.items():
        frame=days[day]; seq=make_sequences(frame,config,day); np.savez_compressed(args.output/f'{split}.npz',**seq)
        future=seq['future_label'].reshape(-1); counts={name:int(np.sum(future==idx)) for name,idx in CLASS_TO_ID.items() if np.any(future==idx)}
        summary[split]={'day':day,'windows':len(frame),'sequences':len(seq['x']),'future_class_counts':counts,'attack_rate_by_horizon':seq['attack'].mean(0).tolist()}
    manifest={'release':args.output.name,'evidence_status':'real_public_dataset','source':'UNSW-NB15 original raw flow CSV partitions','features':FLOW_FEATURES,'history_steps':config.history_steps,'window_seconds':config.window_seconds,'horizons_steps':list(config.horizons),'horizons_seconds':[h*config.window_seconds for h in config.horizons],'split_strategy':f"capture-date split: {split_day['train']} train, {split_day['val']} validation, {split_day['test']} test",'label_mapping_note':'Binary Label is authoritative for attack/onset. attack_cat mapping to AegisNet classes is approximate: Reconnaissance->RECONNAISSANCE, DoS->DDOS_HIGH, all other UNSW attack families->INITIAL_ACCESS_PATTERN.','feature_missingness_note':'UNSW state field is not a raw TCP flag bitmap, so SYN/ACK/RST/FIN/PSH/URG-derived features are set to zero rather than inferred.','victim_supervision':'generic only: NONE for benign, MULTI for attack; UNSW hosts are not mapped into the EVE topology','splits':summary}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8'); print(json.dumps(manifest,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
