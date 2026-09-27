# AEGISNET-WM — 2-minute demo video script

Target duration: **1:50–1:58**. Never exceed 2:00.

## 0:00–0:15 — Problem

Screen: title + simple attack timeline.

Voice: “Traditional IDS tells us an attack is happening after suspicious traffic appears. AEGISNET-WM learns how network state evolves and rolls that state forward, asking what malicious stage is likely in the next 10, 30 and 60 seconds.”

## 0:15–0:35 — Input and architecture

Screen: architecture slide / live dashboard.

Voice: “The system is fully offline. Live mode consumes NetFlow, device telemetry and syslog. Competition file mode accepts PCAP or flow CSV. PCAP extraction adds TTL variance, TCP window, fragmentation, payload-size, timing, scan and retransmission evidence.”

## 0:35–0:55 — File-input demo

Screen: Offline File Analysis page. Upload a prepared PCAP/CSV. Show risk timeline.

Voice: “Each file becomes fixed 10-second network states. Six states form 60 seconds of context. The latent world model forecasts +10, +30 and +60 seconds, predicts the attack stage and maps it to MITRE ATT&CK.”

## 0:55–1:15 — Explainability

Screen: latest forecast cards and “Why this forecast?” section.

Voice: “This is not a black box. Every prediction includes gradient-based feature attribution. PCAP input also shows independent packet evidence such as sequential port activity, TTL variation or retransmissions.”

## 1:15–1:38 — Held-out forecasting proof

Screen: replay run 90 at 16:49:40, then move to 16:50:40.

Voice: “Here is a held-out EVE run excluded from calibration. During reconnaissance, the +60-second calibrated risk crosses threshold at 67.6 percent. Exactly 60 seconds later, the ground truth enters Initial Access. The model is forecasting escalation, not merely relabelling an attack after onset.”

## 1:38–1:52 — Benchmark

Screen: benchmark page.

Voice: “Against logistic regression on the same current-state features, the temporal world model improves macro-F1 at every horizon, with held-out attack AUROC of 0.988, 0.978 and 0.960.”

## 1:52–1:58 — Safety close

Screen: health/guard status.

Voice: “Production guards reject stale, incomplete or out-of-domain evidence. Forecasting remains advisory until strict local promotion gates pass. AEGISNET predicts early—but fails closed when it should.”

## Capture checklist

- 1920×1080 or 1280×720, 30 fps.
- Hide credentials, `.env`, EVE login windows and local paths containing secrets.
- Show the PCAP/CSV uploader, probability timeline, stage/MITRE output, explanation panel, run-90 replay and benchmark table.
- Do not claim packet-fusion benchmark improvement; packet evidence is currently a bounded supporting signal around the validated flow-temporal model.
