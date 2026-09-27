from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "models"))
from offline_inference import analyse_file  # noqa: E402


st.title("Offline PCAP / CSV Attack Forecasting")
st.caption("Fully local inference - no cloud API and no external upload")

uploaded = st.file_uploader(
    "Upload PCAP, PCAPNG or flow CSV",
    type=["pcap", "pcapng", "cap", "csv"],
)
if uploaded is None:
    st.info(
        "Upload traffic to build 10-second network states and run +10/+30/+60 second forecasts."
    )
    st.stop()

suffix = Path(uploaded.name).suffix
with tempfile.NamedTemporaryFile(
    prefix="aegis-upload-", suffix=suffix, delete=False
) as handle:
    handle.write(uploaded.getbuffer())
    temp_path = Path(handle.name)

try:
    with st.spinner("Extracting features and rolling the world model forward..."):
        result = analyse_file(temp_path)
except Exception as exc:
    st.error(f"Analysis failed: {type(exc).__name__}: {exc}")
    st.stop()
finally:
    try:
        temp_path.unlink(missing_ok=True)
    except OSError:
        pass

source = result["source"]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Input", source["input_type"].upper())
c2.metric("States", source["state_count"])
c3.metric("Packet evidence", "YES" if source.get("packet_capture_present") else "NO")
c4.metric("Model", result["model"]["release"])

rows = []
for entry in result["timeline"]:
    for item in entry["forecast"]["horizons"].values():
        rows.append(
            {
                "time": entry["window_end"],
                "horizon_s": item["seconds"],
                "world_risk": item["future_attack_probability"],
                "fused_risk": item["packet_evidence_adjusted_probability"],
                "stage": item["predicted_class"],
                "confidence": item["confidence"],
            }
        )
timeline = pd.DataFrame(rows)
if not timeline.empty:
    fig = go.Figure()
    for horizon in sorted(timeline["horizon_s"].unique()):
        subset = timeline[timeline["horizon_s"] == horizon]
        fig.add_trace(
            go.Scatter(
                x=subset["time"],
                y=subset["fused_risk"],
                mode="lines+markers",
                name=f"+{horizon}s",
            )
        )
    fig.update_layout(
        title="Forecast attack / infiltration risk timeline",
        yaxis_title="Probability",
        yaxis_range=[0, 1],
        xaxis_title="Traffic time",
    )
    st.plotly_chart(fig, use_container_width=True)

latest = result["latest_forecast"]
st.subheader("Latest forward simulation")
cards = st.columns(3)
for col, key in zip(
    cards,
    sorted(latest.get("horizons", {}), key=lambda value: int(value)),
):
    item = latest["horizons"][key]
    with col:
        st.metric(
            f"+{item['seconds']}s risk",
            f"{item['packet_evidence_adjusted_probability']:.1%}",
            f"world {item['future_attack_probability']:.1%}",
        )
        st.write(f"**Stage:** {item['predicted_class']}")
        mitre = item.get("mitre") or {}
        st.write(
            f"**MITRE:** {mitre.get('tactic', 'Unknown')} / "
            f"{mitre.get('technique', 'Unknown')}"
        )
        st.write(f"**Confidence:** {item['confidence']:.1%}")

strong = result.get("strongest_latest_horizon") or {}
if strong:
    st.subheader("Why this forecast?")
    left, right = st.columns(2)
    with left:
        st.markdown("**Temporal world-model drivers**")
        drivers = pd.DataFrame(strong.get("top_features") or [])
        if not drivers.empty:
            columns = [
                column
                for column in ("feature", "description", "attribution")
                if column in drivers
            ]
            st.dataframe(drivers[columns], use_container_width=True, hide_index=True)
        else:
            st.write("No attribution available.")
    with right:
        packet = strong.get("packet_evidence") or {}
        st.markdown("**Packet-level evidence**")
        if packet.get("available"):
            st.metric("Packet evidence score", f"{float(packet['score']):.1%}")
            pdata = pd.DataFrame(packet.get("drivers") or [])
            if not pdata.empty:
                st.dataframe(pdata, use_container_width=True, hide_index=True)
        else:
            st.info(
                "CSV flow input: packet-level fields are explicitly unavailable, not silently imputed."
            )

st.download_button(
    "Download analysis JSON",
    json.dumps(result, indent=2),
    file_name="aegisnet_offline_analysis.json",
    mime="application/json",
)
st.caption(
    "Packet evidence is a bounded supporting signal. Published benchmark metrics remain those of the learned temporal world model."
)
