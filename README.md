# Air-Gapped Predictive Copilot — EVE-NG Network Lab

This workspace contains a reproducible EVE-NG implementation of the network
side of the project:

- MPLS L3VPN provider core with two equal underlay paths.
- Simulated Internet transport.
- Two IKEv2/IPsec-protected DMVPN Phase 3 clouds.
- Named EIGRP overlay with dynamic spoke-to-spoke shortcuts.
- Application-aware steering, QoS, IP SLA, NetFlow v9, syslog and SNMPv3.
- Deterministic congestion, jitter, loss, BGP flap, link-failure and policy-drift scenarios.

The EVE deployer creates the topology through the supported REST API. It does
not contain or download proprietary Cisco images.

## 1. Prerequisites

- EVE-NG reachable from Windows.
- `c7200-adventerprisek9-mz.152-4.S7.image` installed in EVE-NG.
- `linux-netem` and `linux-tinycore-6.4` installed under EVE's Linux template.
- EVE VM configured with roughly 8 GB RAM and four vCPUs.
- EVE `pnet0` bridged to VMware VMnet8 `192.168.58.0/24`. The Windows collector
  is `192.168.58.1`; IOS OOB management uses the static range `.10`–`.18`,
  outside VMnet8's DHCP pool (`.128`–`.254`). The EVE VM is currently `.128`.

The live EVE template reports 512 MB RAM and Idle-PC `0x62f21000` for S7.

## 2. Render Deployable Router Configurations

```powershell
Copy-Item .env.example .env
# Edit .env and replace every CHANGEME value.
python .\tools\render_configs.py
```

Preview configurations with placeholders only:

```powershell
python .\tools\render_configs.py --allow-placeholders
```

## 3. Create the EVE Lab

First inspect the intended deployment without changing EVE:

```powershell
python .\tools\deploy_eve.py --dry-run
```

Then deploy:

```powershell
$env:EVE_URL = 'http://192.168.58.128'
$env:EVE_USERNAME = 'admin'
$env:EVE_PASSWORD = 'your-eve-password'

python .\tools\deploy_eve.py `
  --eve-path '/RS' `
  --router-image 'c7200-adventerprisek9-mz.152-4.S7.image' `
  --netem-image 'linux-netem' `
  --endpoint-image 'linux-tinycore-6.4'
```

The deployer discovers installed C7200 images and prefers S7, then S6/S2. It will
not overwrite an existing lab unless `--replace` is supplied explicitly.
Use `--pro --insecure` for a self-signed EVE Pro HTTPS installation.

## 4. Boot and Configure IOS

```powershell
python .\tools\push_configs.py --start --boot-wait 120
```

The loader:

- Starts the nine routers.
- Handles the initial IOS setup dialogue.
- Pastes each rendered configuration with mode-aware `exit` handling.
- Generates 2048-bit RSA keys.
- Saves the configuration.
- Reports every rejected IOS command.

## 5. Configure Linux Nodes

The stock `linux-netem` image boots with `nodhcp` and automatically bridges
`eth0` to `eth1`. Do not attach an OOB NIC to these nodes: both NICs are the
transparent transport path. `fault_injector.py` opens their EVE consoles and
applies profiles directly, so no SSH service or management address is needed.

Endpoint assignments:

| Node | Command |
|---|---|
| CLIENT-BR1 | `setup_endpoint.sh 10.1.10.10/24 10.1.10.1 client` |
| CLIENT-BR2 | `setup_endpoint.sh 10.2.10.10/24 10.2.10.1 client` |
| SERVICE-HUB | `setup_endpoint.sh 10.10.10.10/24 10.10.10.1 server` |
| APP-DC | `setup_endpoint.sh 10.20.10.10/24 10.20.10.1 server` |

Set `AUTHORIZED_KEY` when running endpoint setup if traffic profiles will be
started remotely. The deployed lab already has these four addresses persisted
in TinyCore's `/opt/bootlocal.sh`; the commands above are rebuild references.

## 6. Run Traffic and Faults

```powershell
.\tools\run_traffic.ps1 -Profile mixed -IdentityFile "$HOME\.ssh\id_ed25519"

python .\tools\fault_injector.py progressive-congestion --stage-seconds 60

python .\tools\fault_injector.py baseline
python .\tools\fault_injector.py bgp-flap --cycles 3 --hold 5
python .\tools\fault_injector.py core-failure --restore-after 30
python .\tools\fault_injector.py policy-drift
python .\tools\fault_injector.py policy-restore
```

## 7. Run the Unified Telemetry Service

One persistent process owns NetFlow v9/IPFIX UDP 2055, syslog UDP 5514 and
parallel IOS SSH polling for IP SLA, tracking, interfaces, CPU, memory and
routing/DMVPN state:

```powershell
python .\telemetry\manage_telemetry.py start -- `
  --bind 192.168.58.1 `
  --poll-interval 15

python .\telemetry\manage_telemetry.py status
python .\telemetry\telemetry_summary.py
```

Stop it cleanly with:

```powershell
python .\telemetry\manage_telemetry.py stop
```

The primary store is `outputs/telemetry.db` in SQLite WAL mode. CSV/JSONL flow
and syslog streams are retained for compatibility with the original collector.
The Cisco App-ID mapping is the verified copy at `telemetry/nbar_table.txt`.
See [docs/telemetry.md](docs/telemetry.md) for schemas, SLA meanings and
operational queries.

## 8. Validate

```powershell
python -m unittest discover -s .\tests -v

$env:EVE_PASSWORD = Read-Host "EVE GUI/API password"
python .\tools\audit_lab.py `
  --eve-url http://192.168.58.128 `
  --eve-path /RS `
  --subnet 192.168.58.0/24
Remove-Item Env:EVE_PASSWORD
```

## 9. Capture Labelled Fault Data

Run reversible baseline/fault/recovery experiments while telemetry and
endpoint traffic are active:

```powershell
$env:EVE_PASSWORD = 'eve'
& 'D:\deep\python.exe' .\experiments\scenario_runner.py jitter `
  --baseline-seconds 30 `
  --fault-seconds 60 `
  --recovery-seconds 45
Remove-Item Env:EVE_PASSWORD
```

The runner supports jitter, loss, transport outages, core failure, policy
drift, BGP flap and progressive congestion. It restores the injected state,
validates DMVPN/IKEv2 and BR1-to-DC recovery, then writes per-device labelled
feature windows to SQLite. See
[docs/experiments.md](docs/experiments.md) for the complete workflow.

## 10. Build a Versioned Dataset

`experiments/campaign_runner.py` creates randomized, resumable campaigns with
run-level splits and mixed traffic. `experiments/dataset_quality.py` exports
raw and derived tables, checksums, a dataset card, Croissant metadata and
publication gates. See
[docs/dataset_protocol.md](docs/dataset_protocol.md) for the scientific
collection protocol and the exact limits on detection versus forecasting
claims.

`audit_lab.py` verifies required interfaces, OSPF, LDP, BGP, EIGRP, DMVPN,
IKEv2 and a real BR1-client-to-DC ping. It then scans SSH, asks each reachable
IOS device for its configured hostname, and compares the resulting IP map with
the EVE inventory. Results are written to `outputs/lab-audit.json`; exit code
`0` means every check passed.

After a fresh Dynamips deployment, use `--repair-ssh` once. It generates
missing RSA keys, installs the IOS-compatible local account from the private
`.env`, reasserts VTY SSH authentication and saves NVRAM. Normal audits are
read-only and should omit this flag.

See [docs/topology.md](docs/topology.md) for links, addressing, protocol roles,
fault locations and IOS acceptance commands.

## 11. Temporal World Model Forecasting

The project now includes a separate temporal world-model layer in `models/world_model/`. It consumes six 10-second states, rolls a learned latent state forward, and forecasts +10/+30/+60-second attack class, attack onset, infiltration probability and likely next victim. The live service enriches forecasts with topology paths, MITRE ATT&CK context, feature attribution, operator playbooks, a hash-chained audit trail and incident briefs.

The deployed production-advisory temporal artifact is `genis-world-v1`, trained
on the real scenario-disjoint GeNIS release. Public/shadow and next-stage
models remain evidence-only unless their explicit local-domain promotion gates
pass. See [docs/world_model.md](docs/world_model.md) for training, public-data
import, multi-seed evaluation and evidence-status rules.

## 12. EVE Cyber Forecast Validation

The local-domain validation path is now implemented separately from the legacy
network-fault campaign.  `experiments/cyber_scenario_runner.py` records exact
phase boundaries for bounded `BENIGN -> RECON -> INITIAL_ACCESS` and
`BENIGN -> RECON -> DDoS` progressions, plus long benign soak runs.  Targets are
fixed to the controlled EVE endpoints; the runner does not accept arbitrary
victim addresses.

```powershell
$env:EVE_PASSWORD = Read-Host "EVE password"
D:\deep\python.exe .\experiments\cyber_scenario_runner.py recon-initial-access --split train
D:\deep\python.exe .\experiments\cyber_scenario_runner.py benign-soak --split test --soak-seconds 1800

D:\deep\python.exe .\models\world_model\lab_temporal_dataset.py `
  --output .\dataset\releases\eve-cyber-temporal-v1

D:\deep\python.exe .\models\world_model\eve_shadow_calibration.py `
  --data-dir .\dataset\releases\eve-cyber-temporal-v1

D:\deep\python.exe .\experiments\forecast_evaluator.py --signal eve-calibrated
D:\deep\python.exe .\tools\evidence_bundle.py --run-tests
```

Public-dataset models, the EVE-calibrated stacker, and the separate GeNIS
next-stage model remain evidence-only.  They cannot change the operator-facing
health state.  See [docs/eve_forecasting_protocol.md](docs/eve_forecasting_protocol.md)
for the P0-P3 validation and promotion gates.

## 13. SIH / NTRO Competition Mode

AEGISNET-WM now exposes the complete competition-facing workflow in addition to
the live NOC console.

### Offline PCAP / CSV inference

Start the normal Streamlit UI and select **Offline File Analysis** from the
sidebar:

```powershell
D:\deep\python.exe -m streamlit run .\ui\app.py --server.port 8501
```

The page accepts `.pcap`, `.pcapng`, `.cap`, and common NetFlow-style `.csv`
files. Processing is entirely local. PCAP inputs extract TTL statistics, TCP
window statistics, IP fragmentation, payload-size distribution, packet IAT,
port-scan signatures and TCP retransmission evidence. CSV inputs are normalized
to the same 10-second flow-state representation and explicitly report packet
evidence as unavailable rather than inventing values.

Two harmless ready-to-upload inputs are included:

```text
samples/aegisnet_demo_recon.pcap
samples/aegisnet_demo_flows.csv
```

They are generated by `tools/build_demo_inputs.py`; no packets are transmitted.
The demo PCAP contains ordinary HTTPS-like metadata followed by synthetic
sequential destination-port probes. On the current release it builds seven
temporal states with packet evidence present and predicts the RECONNAISSANCE
stage at all three forecast horizons.

CLI equivalent:

```powershell
D:\deep\python.exe .\models\offline_inference.py .\sample.pcap `
  --output .\outputs\offline-analysis.json
```

The output contains a +10/+30/+60 risk timeline, predicted attack stage,
MITRE ATT&CK mapping, gradient-times-input feature attribution and, when PCAP is
available, a separate bounded packet-evidence explanation.

### Same-feature logistic benchmark

```powershell
D:\deep\python.exe .\tools\competition_benchmark.py
```

This writes `outputs/competition/benchmark.{json,csv,md}`. The logistic
regression baseline receives the same current-state feature vector and the same
future targets as the world model. The difference is temporal context: the
world model consumes six consecutive 10-second states and learns transition
dynamics before rolling forward.

### Full bounded attack-stage progression

The controlled EVE lab supports a demonstration progression matching the stage
mapping required by the challenge:

```powershell
D:\deep\python.exe .\experiments\cyber_scenario_runner.py full-kill-chain `
  --split test --campaign-id competition-demo `
  --baseline-seconds 30 --recon-seconds 30 --stage-seconds 30 `
  --recovery-seconds 30
```

The sequence is:

`BENIGN -> RECONNAISSANCE -> INITIAL_ACCESS_PATTERN -> LATERAL_MOVEMENT -> C2_BEACON_PATTERN -> EXFILTRATION_LIKE -> BENIGN`

All sources/targets are fixed controlled lab endpoints. Initial Access is only a
repeated-connect network pattern, lateral movement is connection-pattern only,
C2 is a small periodic beacon, and exfiltration-like traffic uses zero-filled
synthetic payloads. The runner does not accept arbitrary victims.

### Reproducible training and weights

Training code is under `models/world_model/`; the frozen configuration is
`config/world_model_training.json`. Binary model weights are intentionally not
stored in git history. Build the exact distributable model pack with:

```powershell
D:\deep\python.exe .\tools\package_models.py
```

The command creates `dist/aegisnet-model-pack-v1.zip` plus a SHA-256 file. The
competition release uploads those files as private GitHub Release assets so an
evaluator can reproduce inference without bloating source history.

### Compliance audit

```powershell
D:\deep\python.exe .\tools\competition_compliance.py
```

The audit fails closed if packet extraction, file upload inference, temporal
weights, explainability, same-feature logistic evidence, kill-chain stage
coverage, training/weight reproducibility, or submission sources are missing.
The rendered architecture document, five-slide presentation and two-minute demo
assets are generated from the versioned `submission/` sources.

### Evidence boundary

`genis-world-v1` is the benchmarked learned **flow-temporal** world model.
Packet-level PCAP features are fully processed and fused as bounded supporting
evidence in competition file inference, but AEGISNET does not claim a
packet-fusion benchmark improvement until a labelled packet-level training
corpus has been validated under the same split discipline. This distinction is
intentional and prevents unsupported performance claims.
