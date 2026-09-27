# AEGISNET-WM — Architecture Document

**SIH Problem Statement 26153 · NTRO · AI based Network Attack Forecasting from Network Traffic Data**

## 1. Objective and design principle

Traditional IDS models classify the present flow. AEGISNET-WM instead models a network as a time-evolving state and learns transition dynamics over six consecutive 10-second observations. The production-advisory world model rolls its latent state forward to +10, +30 and +60 seconds and outputs future attack probability, attack stage, onset/infiltration probability, likely victim and per-prediction feature attribution.

The system is deliberately split into two authority planes. The **present-state detector** is the only component eligible for operator alert authority after strict local acceptance. The **predictive world-model plane** is advisory: it may raise WATCH/forecast evidence but cannot independently change the authoritative alert state. Telemetry-health, out-of-domain, incomplete-history and artifact-integrity gates fail closed.

## 2. Data and state representation

### Flow-level state

NetFlow v9/IPFIX and imported flow CSVs are aggregated into fixed 10-second windows. The 29-feature security state includes flow/packet/byte counts, unique and new hosts/ports, TCP flag counts and ratios, host/port fan-out, destination-port entropy, sequential-port score, east-west/north-south activity, inter-arrival-time statistics and flow-duration statistics.

### Packet-level state

PCAP/PCAPNG files are parsed locally with Scapy. Payload contents are not persisted. Metadata features include TTL mean/variance/range, TCP receive-window statistics, IP fragmentation flags, payload-size distribution, packet inter-arrival statistics, packet-level destination-port spread and conservative TCP retransmission detection. Packet evidence is fused as a bounded supporting signal in the offline competition path; the published GeNIS benchmark remains the learned flow-temporal core because the GeNIS release supplies the validated flow representation.

### Network-health context

The live lab additionally collects IP SLA, interface, QoS, device/routing state and syslog. These are retained as contextual evidence and hard-negative network-fault data so cyber detection does not confuse congestion/loss/outage with attack traffic.

## 3. Model and inference path

`genis-world-v1` is a learned latent transition model trained on scenario-disjoint real cyber-range sequences. Input history is 60 seconds (6 × 10-second states); the learned latent transition is rolled forward for 1, 3 and 6 steps. Heads predict stage class, attack probability, state-change probability, attack onset, infiltration and victim class. Gradient × input attribution ranks the traffic features that drove each horizon prediction; stage labels are mapped to MITRE ATT&CK.

The same-feature logistic baseline receives the current state only, while the world model receives the six-state history. On held-out GeNIS test data, world-model macro-F1 is **0.368 / 0.369 / 0.370** at +10/+30/+60 seconds versus logistic **0.253 / 0.226 / 0.205**. Attack AUROC is **0.988 / 0.978 / 0.960** and AUPRC **0.939 / 0.861 / 0.625**. The multi-seed headline remains 0.992/0.943, 0.975/0.787 and 0.952/0.642 AUROC/AUPRC respectively.

## 4. Local EVE validation and demo

The EVE-NG environment contains MPLS L3VPN, dual encrypted DMVPN transports, branches, hub/DC endpoints, application traffic, faults and bounded cyber progressions. Scenario runners write exact ground-truth phase timestamps. A held-out demo campaign not used by EVE calibration produced the progression BENIGN → RECONNAISSANCE → INITIAL_ACCESS_PATTERN → recovery. During reconnaissance, the calibrated +60-second risk crossed its threshold **60 seconds before INITIAL_ACCESS_PATTERN actually began**.

The bounded full-kill-chain runner additionally generates network-pattern-only Reconnaissance → Initial Access → Lateral Movement → Command & Control → Exfiltration-like stages. Targets and sources are fixed to controlled lab nodes; no arbitrary victim is accepted and exfiltration uses zero-filled synthetic payloads only.

## 5. Production and offline demo surfaces

The live Streamlit NOC console shows current state, +10/+30/+60 forecasts, MITRE mapping, likely path/victim, top drivers and operator recommendations. A separate offline page accepts **PCAP/PCAPNG or CSV**, builds the same temporal states, runs the world model locally, displays the probability timeline and attack stages, and shows both temporal-model drivers and packet-level evidence. No cloud API is required.

All model directories have SHA-256 manifests; the local OOD envelope is hash-pinned; SQLite runs in WAL mode with integrity checks; forecasts are hash-chain audited; source releases are git-tagged and rollback backups are generated. Automated authority remains disabled until the exact locked acceptance campaign satisfies minimum volume, FPR, recall, false-alert/hour and hard-negative gates.

## 6. Reproducibility

Source, dataset builders, training scripts, pinned dependencies and `config/world_model_training.json` are versioned. Binary weights are kept out of git history and packaged by `tools/package_models.py` into a SHA-256-verifiable GitHub Release asset. `tools/competition_benchmark.py` regenerates the same-feature baseline table, and `tools/competition_compliance.py` fails closed if a required SIH deliverable or implementation surface is missing.
