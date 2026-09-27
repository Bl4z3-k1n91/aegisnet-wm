# Slide 1 — From Intrusion Detection to Attack Forecasting

**AEGISNET-WM · SIH 26153 · NTRO**

- Static IDS: “What looks malicious now?”
- AEGISNET-WM: “Given the evolving network state, what happens next?”
- 6 × 10-second history → learned latent transition → +10/+30/+60-second rollout
- Offline, open-source software path; live EVE-NG + PCAP/CSV file demo

Visual: one horizontal timeline: BENIGN → RECON → predicted escalation → INITIAL ACCESS.

---

# Slide 2 — Two-Level Network State + World Model

- **Flow:** NetFlow/IPFIX, flags, hosts/ports, bytes/packets, duration, IAT, fan-out, scan signatures
- **Packet:** TTL variance, TCP window, fragment flags, payload distribution, packet IAT, retransmissions, port spread
- **Temporal model:** 60-second context, latent state transition, 3 forecast horizons
- Outputs: attack probability, MITRE stage, onset/infiltration, victim, top contributing features

Visual: Flow + PCAP → state windows → latent world model → 3 forecast cards.

---

# Slide 3 — Evidence, Not a Fancy Classifier

Same-feature held-out GeNIS benchmark:

| Horizon | World macro-F1 | Logistic macro-F1 | Attack AUROC | AUPRC |
|---|---:|---:|---:|---:|
| +10s | 0.368 | 0.253 | 0.988 | 0.939 |
| +30s | 0.369 | 0.226 | 0.978 | 0.861 |
| +60s | 0.370 | 0.205 | 0.960 | 0.625 |

- Logistic sees the same current feature vector; world model sees six sequential states.
- Multi-seed AUROC/AUPRC: 0.992/0.943, 0.975/0.787, 0.952/0.642.
- Held-out EVE replay: +60 forecast crossed threshold 60 seconds before Initial Access.

---

# Slide 4 — Live Demo & Explainability

1. Upload PCAP/CSV **or** watch live EVE telemetry.
2. See +10/+30/+60 probability timeline.
3. Predicted stage maps to MITRE ATT&CK.
4. “Why?” panel shows gradient × input drivers and PCAP evidence.
5. Full bounded progression supports Recon → Initial Access → Lateral Movement → C2 → Exfiltration-like.

Visual: screenshot of offline uploader + risk timeline + “Why this forecast?” panel.

---

# Slide 5 — Production-Safe by Design

- Telemetry health + complete history + OOD guard + artifact SHA-256 before advisory.
- Public/shadow/next-stage forecasts **cannot** override authoritative operator state.
- Hash-chained prediction audit, WAL database, health/readiness endpoints, rollback release.
- Temporal authority challenger is locked behind an exact unseen acceptance campaign; no metric gaming.
- Private evaluator repository + reproducible model-weight release pack.

**Takeaway:** AEGISNET-WM forecasts how an intrusion is likely to evolve, explains the evidence, and knows when not to trust itself.
