from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st


ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "outputs" / "competition" / "benchmark.json"
DEMO = ROOT / "outputs" / "demo" / "latest.json"
READINESS = ROOT / "outputs" / "production-readiness.json"

st.title("Benchmark & Evidence")
st.caption("Held-out evidence, same-feature baseline comparison and safety gates")
if not BENCH.exists():
    st.error("Run tools/competition_benchmark.py first.")
    st.stop()

bench = json.loads(BENCH.read_text(encoding="utf-8"))
st.success(bench["same_feature_contract"])
rows = pd.DataFrame(bench["rows"])
st.dataframe(rows, use_container_width=True, hide_index=True)
st.markdown("### What the comparison isolates")
st.write(
    "The logistic baseline sees the same current-state feature vector. The temporal world model sees six consecutive 10-second states and performs learned latent rollouts, isolating the value of temporal dynamics rather than changing the feature set."
)

if DEMO.exists():
    demo = json.loads(DEMO.read_text(encoding="utf-8"))
    escalation = demo.get("best_pre_escalation_warning")
    if escalation:
        st.metric(
            "Held-out EVE escalation warning lead",
            f"{float(escalation['lead_seconds']):.0f}s",
        )
        st.write(
            f"Run {demo['run']['id']} was held out from the EVE calibration campaign and forecast **{escalation['target_stage']}** during the preceding stage."
        )

if READINESS.exists():
    readiness = json.loads(READINESS.read_text(encoding="utf-8"))
    c1, c2, c3 = st.columns(3)
    c1.metric("Platform ready", "YES" if readiness.get("platform_ready") else "NO")
    c2.metric(
        "Advisory ready",
        "YES" if readiness.get("production_advisory_release_ready") else "NO",
    )
    c3.metric(
        "Auto authority",
        "YES" if readiness.get("automated_alert_authority_ready") else "LOCKED",
    )
st.warning(bench["warning"])
