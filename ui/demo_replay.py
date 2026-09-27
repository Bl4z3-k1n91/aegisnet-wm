#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st


ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / 'outputs' / 'demo' / 'latest.json'

st.set_page_config(page_title='AegisNet-WM Demo Replay', page_icon='⌁', layout='wide')
st.title('AEGISNET-WM · Held-Out Attack Forecast Replay')
st.caption('Recorded EVE telemetry · held-out demo campaign · forecast outputs remain shadow evidence')

if not REPLAY.exists():
    st.error('Demo replay package is missing. Run tools/build_demo_replay.py first.')
    st.stop()

data = json.loads(REPLAY.read_text(encoding='utf-8'))
timeline = data.get('timeline') or []
if not timeline:
    st.error('Replay contains no usable timeline rows.')
    st.stop()

run = data['run']
c1, c2, c3, c4 = st.columns(4)
c1.metric('Run', run['id'])
c2.metric('Scenario', run['scenario'])
c3.metric('Held out', 'YES' if data.get('held_out_demo') else 'NO')
warning = data.get('best_pre_onset_warning')
escalation = data.get('best_pre_escalation_warning')
c4.metric('Pre-escalation lead', f"{escalation['lead_seconds']:.0f}s" if escalation else 'none')

index = st.slider('Replay position', 0, len(timeline) - 1, 0)
row = timeline[index]
st.subheader(f"{row['timestamp'][11:19]} · Ground truth now: {row['truth_now']}")

cols = st.columns(3)
for col, seconds in zip(cols, ('10', '30', '60')):
    h = row['horizons'][seconds]
    probability = float(h['calibrated_attack_probability'])
    threshold = float(h['calibrated_threshold'])
    col.metric(
        f'+{seconds}s attack risk',
        f'{probability:.1%}',
        f"threshold {threshold:.1%}",
    )
    col.write(f"Future truth: **{h['truth_future']}**")
    col.write(f"World stage: **{h['world_predicted_class']}**")
    col.write(f"Shadow alert: **{'YES' if h['calibrated_shadow_alert'] else 'NO'}**")

next_stage = row.get('next_stage') or {}
st.info(
    f"Next-stage shadow model: **{next_stage.get('predicted_next_stage','UNKNOWN')}** "
    f"({float(next_stage.get('confidence') or 0):.1%}) · alert authority = false"
)

if escalation:
    st.success(
        f"FORECAST HIT: during reconnaissance, the +{escalation['horizon_seconds']}s calibrated "
        f"forecast crossed threshold {escalation['lead_seconds']:.0f}s before "
        f"{escalation['target_stage']}."
    )
elif warning:
    st.success(f"Pre-onset warning lead: {warning['lead_seconds']:.0f}s")

st.markdown('### Ground-truth phase transitions')
st.table(data.get('phase_transitions') or [])

st.markdown('### Demo narrative')
st.write(
    'Move the slider from the benign phase into reconnaissance and then initial access. '
    'The three horizon cards show how future-attack risk evolves while the exact future '
    'ground truth is displayed beside it. This replay uses a campaign excluded from the '
    'EVE calibration dataset.'
)

st.warning('Safety/authority guard: public, calibrated, and next-stage models are evidence-only. They do not control the operator alert state.')
