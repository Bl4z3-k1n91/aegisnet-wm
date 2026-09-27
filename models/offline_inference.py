"""Competition-facing offline PCAP/CSV inference pipeline."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "features"))
sys.path.insert(0, str(ROOT / "models" / "world_model"))
sys.path.insert(0, str(ROOT / "intelligence"))

from offline_inputs import build_offline_states  # noqa: E402
from inference import StateHistory, WorldForecaster  # noqa: E402
from mitre import enrich_forecast  # noqa: E402


DEFAULT_WORLD = ROOT / "models" / "artifacts" / "genis-world-v1"


FEATURE_DESCRIPTIONS = {
    "sequential_port_score": "Sequential destination-port probing signature",
    "max_port_fanout": "Large number of destination ports reached by one source",
    "syn_only_count": "SYN packets without matching ACK activity",
    "syn_ack_ratio": "SYN-to-ACK imbalance",
    "new_dst_hosts": "Previously unseen destination hosts",
    "new_dst_ports": "Previously unseen destination ports",
    "rst_ratio": "Connection-reset ratio",
    "iat_cv": "Flow inter-arrival burstiness",
    "packet_ttl_std": "TTL variance across packets",
    "packet_tcp_window_std": "TCP receive-window variability",
    "packet_fragmented_count": "IP fragmentation activity",
    "packet_retransmission_ratio": "Repeated TCP sequence/payload activity",
    "packet_unique_dst_ports": "Packet-level destination-port spread",
    "packet_payload_p95": "95th percentile packet payload size",
}


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def packet_evidence(state: dict[str, Any]) -> dict[str, Any]:
    """Return bounded, explicitly non-authoritative packet-level evidence."""

    if not int(state.get("packet_capture_present") or 0):
        return {"available": False, "score": 0.0, "drivers": []}
    count = max(float(state.get("packet_event_count") or 0.0), 1.0)
    window_mean = max(float(state.get("packet_tcp_window_mean") or 0.0), 1.0)
    components = {
        "packet_unique_dst_ports": _bounded(float(state.get("packet_unique_dst_ports") or 0.0) / 32.0),
        "sequential_port_score": _bounded(float(state.get("sequential_port_score") or 0.0)),
        "packet_retransmission_ratio": _bounded(float(state.get("packet_retransmission_ratio") or 0.0) / 0.10),
        "packet_fragmented_count": _bounded(float(state.get("packet_fragmented_count") or 0.0) / max(count * 0.08, 1.0)),
        "packet_ttl_std": _bounded(float(state.get("packet_ttl_std") or 0.0) / 12.0),
        "packet_tcp_window_std": _bounded((float(state.get("packet_tcp_window_std") or 0.0) / window_mean) / 0.8),
    }
    weights = {
        "packet_unique_dst_ports": 0.25,
        "sequential_port_score": 0.25,
        "packet_retransmission_ratio": 0.15,
        "packet_fragmented_count": 0.10,
        "packet_ttl_std": 0.10,
        "packet_tcp_window_std": 0.15,
    }
    score = sum(components[name] * weights[name] for name in components)
    drivers = [
        {
            "feature": name,
            "score": components[name],
            "weighted_score": components[name] * weights[name],
            "description": FEATURE_DESCRIPTIONS.get(name, name),
        }
        for name in sorted(
            components,
            key=lambda item: components[item] * weights[item],
            reverse=True,
        )
        if components[name] > 0
    ][:5]
    return {"available": True, "score": _bounded(score), "drivers": drivers}


def analyse_file(path: Path, *, artifact: Path = DEFAULT_WORLD) -> dict[str, Any]:
    states, source = build_offline_states(path)
    forecaster = WorldForecaster(artifact)
    history = StateHistory(maxlen=max(12, forecaster.config.history_steps))
    timeline: list[dict[str, Any]] = []
    for state in states:
        history.append(state)
        forecast = enrich_forecast(forecaster.forecast(history.values(), top_features=8))
        packet = packet_evidence(state)
        for item in forecast.get("horizons", {}).values():
            world_probability = float(item.get("future_attack_probability") or 0.0)
            # The learned temporal world model remains the benchmarked core.
            # Packet evidence can only add a bounded 20% supporting term.
            adjusted = 1.0 - (1.0 - world_probability) * (1.0 - 0.20 * float(packet["score"]))
            item["packet_evidence"] = packet
            item["packet_evidence_adjusted_probability"] = _bounded(adjusted)
            item["fusion_status"] = "FLOW_PLUS_PACKET" if packet["available"] else "FLOW_ONLY"
            for feature in item.get("top_features", []):
                name = str(feature.get("feature"))
                feature["description"] = FEATURE_DESCRIPTIONS.get(name, name)
        timeline.append(
            {
                "window_start": state["window_start"],
                "window_end": state["window_end"],
                "packet_capture_present": bool(state.get("packet_capture_present")),
                "state": state,
                "forecast": forecast,
            }
        )
    last = timeline[-1]["forecast"] if timeline else {"horizons": {}}
    strongest: dict[str, Any] | None = None
    for key, item in last.get("horizons", {}).items():
        candidate = {"horizon_steps": int(key), **item}
        if strongest is None or float(candidate.get("packet_evidence_adjusted_probability") or 0.0) > float(
            strongest.get("packet_evidence_adjusted_probability") or 0.0
        ):
            strongest = candidate
    return {
        "schema_version": 1,
        "mode": "OFFLINE_FILE_ANALYSIS",
        "offline": True,
        "cloud_dependencies": False,
        "source": source,
        "model": {
            "release": forecaster.metadata["model_release"],
            "evidence_status": forecaster.metadata["evidence_status"],
            "history_steps": forecaster.config.history_steps,
            "horizons_seconds": [
                step * forecaster.config.window_seconds
                for step in forecaster.config.horizons
            ],
            "core_world_model_features": list(forecaster.features),
            "packet_fusion": (
                "bounded supporting evidence; published benchmark metrics remain "
                "those of the learned temporal world model"
            ),
        },
        "timeline": timeline,
        "latest_forecast": last,
        "strongest_latest_horizon": strongest,
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_WORLD)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyse_file(args.input, artifact=args.artifact)
    body = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    else:
        print(body, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
