#!/usr/bin/env python3
from __future__ import annotations
import json, sqlite3
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'intelligence'))
from audit_chain import verify

DB=ROOT/'outputs'/'telemetry.db'

def main()->int:
    c=sqlite3.connect(f'file:{DB.as_posix()}?mode=ro',uri=True); c.row_factory=sqlite3.Row
    try:
        current=c.execute("SELECT created_at,event_time,predicted_label,confidence,cyber_risk,risk_band FROM analysis_predictions WHERE source='LIVE' ORDER BY id DESC LIMIT 1").fetchone()
        exists=c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='forecast_predictions'").fetchone()
        forecast=c.execute("SELECT * FROM forecast_predictions ORDER BY id DESC LIMIT 1").fetchone() if exists else None
    finally:c.close()
    print('CURRENT')
    print(json.dumps(dict(current) if current else {'state':'BENIGN_IDLE'},indent=2))
    print('\nFORECAST')
    if forecast:
        doc=dict(forecast); doc['forecast_json']=json.loads(doc['forecast_json']); print(json.dumps(doc,indent=2))
    else: print(json.dumps({'state':'waiting_for_forecast'},indent=2))
    print('\nAUDIT')
    print(json.dumps(verify(),indent=2)); return 0
if __name__=='__main__': raise SystemExit(main())
