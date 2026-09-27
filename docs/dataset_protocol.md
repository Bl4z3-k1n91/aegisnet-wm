# Predictive Copilot Dataset Protocol

## Scientific Claims

This dataset supports three different tasks. They must not be conflated:

1. **Detection:** classify the current baseline/fault/recovery state.
2. **Diagnosis:** identify the fault family, severity and affected transport.
3. **Forecasting:** predict a future staged fault from windows ending before its
   first fault phase. Only `fault_within_30s` and `fault_within_60s` labels are
   valid forecasting targets.

Abrupt outages do not contain engineered precursors and therefore support
detection/diagnosis, not a causal claim of prediction. Progressive congestion
provides controlled precursor stages.

## Collection Design

- The randomized unit is a complete scenario run.
- Train, validation and test assignments occur at run level before collection.
- Overlapping windows from one run never cross splits.
- Fault order is seeded and shuffled.
- Jitter and loss use light, moderate and severe parameterizations.
- Traffic rotates evenly across ping, bulk, business, voice and mixed profiles.
- Every run contains baseline, fault and recovery phases with exact UTC bounds.
- A global restore normalizes both netem links and every router fault point.
- Failed/interrupted runs remain auditable and are not silently relabelled.

The `copilot-rich-v1` first tranche contains 60 planned runs:

| Fault family | Planned runs |
|---|---:|
| MPLS jitter | 15 |
| MPLS loss | 15 |
| Progressive congestion | 5 |
| MPLS outage | 5 |
| Internet outage | 5 |
| Provider core path failure | 5 |
| BGP instability | 5 |
| QoS policy drift | 5 |

Its deterministic split plan contains 43 train, 7 validation and 10 test runs.
Each traffic profile occurs exactly 12 times.

## Raw Modalities

- NetFlow v9/IPFIX five-tuples, DSCP, interfaces, packet/byte counts and NBAR.
- IP SLA per operation/transport/target, RTT, return code and counter deltas.
- Interface state, rates, errors and drops.
- MQC QoS class offered/drop rates, counters, drop deltas and shaper rate.
- CPU, memory, reachability and BGP/OSPF/EIGRP/DMVPN/IKEv2 state.
- IOS syslog with facility and severity.

## Derived Tables

`device_feature_windows` stores device health, routing minima, interface
statistics, DSCP byte volumes, application diversity and syslog features.

`sla_feature_windows` is normalized by device and operation ID. It stores
sample count, mean, standard deviation, min, median, p95, max, MAD, coefficient
of variation, temporal slope, result deltas and successful-sample ratio.

`qos_feature_windows` is normalized by device/interface/policy/class. It stores
offered/drop rates, counter deltas and configured shape rates.

Default windows are 30 seconds wide with a 10 second stride. Every row carries
run, phase, scenario, severity, campaign, split and forecast-horizon metadata.

## Commands

Start the collector:

```powershell
& 'D:\deep\python.exe' .\telemetry\manage_telemetry.py start -- `
  --bind 192.168.58.1 --poll-interval 5
```

Launch a resumable campaign:

```powershell
$env:EVE_PASSWORD = 'eve'
& 'D:\deep\python.exe' .\experiments\campaign_runner.py `
  --campaign-id copilot-rich-v1 `
  --repeats 5 `
  --baseline-seconds 75 `
  --fault-seconds 90 `
  --recovery-seconds 60 `
  --stage-seconds 45
```

Inspect progress:

```powershell
& 'D:\deep\python.exe' .\experiments\campaign_monitor.py copilot-rich-v1
```

Export and run quality gates:

```powershell
& 'D:\deep\python.exe' .\experiments\dataset_quality.py `
  --campaign-id copilot-rich-v1 --export
```

## Publication Gates

The exporter intentionally refuses to call a release publication-ready until:

- collection is complete with no failed runs;
- at least 30 runs and at least five runs per fault family exist;
- train, validation and test splits all exist;
- at least 95% of SLA windows contain three or more samples;
- recovery windows retain full reachability;
- QoS telemetry is present;
- a release license is selected;
- a persistent identifier is assigned;
- an independent reconstruction/replication is completed.

NeurIPS currently expects reproducible code/data, statistical uncertainty,
asset documentation, licensing, long-term preservation, persistent
identifiers and machine-readable metadata. The release generator creates a
checksummed manifest, dataset card and Croissant/RAI draft, but the owner must
still select a legally appropriate license and deposit the final release in a
DOI-backed repository.

## Known Limitations

- One EVE-NG topology and one legacy IOS family do not establish production
  generalization.
- Workloads are synthetic and contain no human-user traffic.
- TinyCore QoS workloads use dependency-free UDP generators with reversible
  iptables DSCP marking.
- Emulator scheduling contributes latency noise and must be reported.
- Cisco/EVE images are not redistributed.
- OOB addresses and collector address must be anonymized before public release.
