from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT=Path(__file__).resolve().parents[2]
TRAIN=Path(__file__).with_name('train.py')
DEFAULT_DATA=ROOT/'dataset'/'releases'/'ntro-world-bootstrap-v1'
DEFAULT_ROOT=ROOT/'models'/'artifacts'/'ntro-world-multiseed-v1'


def ci(values:list[float])->dict[str,float]:
    arr=np.asarray(values,dtype=float); mean=float(arr.mean()); std=float(arr.std(ddof=1)) if len(arr)>1 else 0.0
    half=1.96*std/(len(arr)**0.5) if len(arr)>1 else 0.0
    return {'mean':mean,'std':std,'ci95_low':mean-half,'ci95_high':mean+half}


def main()->int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--seeds',default='11,23,37'); p.add_argument('--epochs',type=int,default=14); p.add_argument('--data-dir',type=Path,default=DEFAULT_DATA); p.add_argument('--output-root',type=Path,default=DEFAULT_ROOT); args=p.parse_args()
    seeds=[int(x) for x in args.seeds.split(',') if x.strip()]; args.output_root.mkdir(parents=True,exist_ok=True)
    records=[]
    for seed in seeds:
        out=args.output_root/f'seed-{seed}'
        cmd=[sys.executable,str(TRAIN),'--epochs',str(args.epochs),'--batch-size','128','--seed',str(seed),'--data-dir',str(args.data_dir),'--output-dir',str(out)]
        print('running seed',seed,flush=True); subprocess.run(cmd,check=True)
        records.append({'seed':seed,'metrics':json.loads((out/'metrics.json').read_text(encoding='utf-8'))})
    aggregate={'seeds':seeds,'evidence_status':records[0]['metrics']['evidence_status'],'horizons':{}}
    for horizon in ('1','3','6'):
        aggregate['horizons'][horizon]={}
        keys=['accuracy','macro_f1','brier_multiclass','nll','benign_false_positive_rate','attack_auroc','attack_auprc','onset_auroc','onset_auprc','infiltration_auroc','infiltration_auprc','victim_accuracy']
        for key in keys:
            vals=[float(r['metrics']['world_model'][horizon][key]) for r in records if key in r['metrics']['world_model'][horizon]]
            if vals: aggregate['horizons'][horizon][key]=ci(vals)
    lead=[float(r['metrics']['lead_time']['median_warning_seconds']) for r in records]
    aggregate['median_warning_seconds']=ci(lead)
    (args.output_root/'aggregate.json').write_text(json.dumps(aggregate,indent=2)+'\n',encoding='utf-8'); print(json.dumps(aggregate,indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
