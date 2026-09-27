# Unified Telemetry Service

## Inputs

| Source | Transport | Stored data |
|---|---|---|
| NetFlow v9/IPFIX | UDP 2055 | Five-tuple, DSCP, interfaces, counters, timing and Cisco App-ID |
| IOS syslog | UDP 5514 | Exporter, facility, severity and message |
| IOS SSH poller | TCP 22 | IP SLA, tracking, interfaces, CPU, memory and protocol state |
| IOS MQC poller | TCP 22 | Per-class offered/drop rate, counters, drops and shaper rate |

NetFlow templates are keyed by version, exporter, observation domain and
template ID. This prevents one router's template from decoding another
router's records. Cisco App-ID uses the same vendor/engine/selector idea as the
original collector and the copied `telemetry/nbar_table.txt` mapping.

The SSH poller uses the repository's current static OOB inventory by default.
Pass `--device-map <audit.json>` explicitly when a newly generated audit map
should override those addresses. This avoids silently loading a stale audit
file after the EVE/VMnet management network changes.

## Service Operation

```powershell
python .\telemetry\manage_telemetry.py start -- `
  --bind 192.168.58.1 `
  --poll-interval 15

python .\telemetry\manage_telemetry.py status
python .\telemetry\telemetry_summary.py
python .\telemetry\manage_telemetry.py stop
```

Use a shorter interval such as 5–10 seconds during a fault demonstration.
Fifteen seconds is the normal baseline interval.

Files:

- `outputs/telemetry.db`: primary SQLite database in WAL mode.
- `outputs/telemetry-status.json`: machine-readable service heartbeat.
- `outputs/telemetry-service.log`: collector and polling log.
- `outputs/flows-live.csv` and `flows-live.jsonl`: compatibility flow streams.
- `outputs/syslog-live.jsonl`: compatibility syslog stream.

## SQLite Tables

- `flows`: normalized NetFlow v9/IPFIX records and original JSON.
- `syslog_events`: normalized IOS syslog.
- `sla_samples`: transport/target, RTT, return code and cumulative/delta results.
- `interface_samples`: state, rates and cumulative/delta errors and drops.
- `qos_samples`: MQC interface/policy/class rates, counters and drop deltas.
- `device_samples`: reachability, CPU, memory and routing/DMVPN counts.
- `service_events`: collector lifecycle and internal errors.

## IP SLA Meaning

| Device | Operation | Transport | Target |
|---|---:|---|---|
| BR1/BR2 | 101 | MPLS Tunnel100 | HUB |
| BR1/BR2 | 102 | Internet Tunnel200 | HUB |
| BR1/BR2 | 111 | MPLS Tunnel100 | DC |
| BR1/BR2 | 112 | Internet Tunnel200 | DC |
| HUB | 111 | MPLS Tunnel100 | DC |
| HUB | 112 | Internet Tunnel200 | DC |
| DC | 101 | MPLS Tunnel100 | HUB |
| DC | 102 | Internet Tunnel200 | HUB |

`success_delta` and `failure_delta` are calculated between polls. These are
more useful for prediction than IOS's lifetime cumulative counters.

## Useful Queries

Latest SLA state:

```sql
SELECT device, operation_id, rtt_ms, return_code, failure_delta, track_state
FROM sla_samples
ORDER BY id DESC
LIMIT 20;
```

Recent interface degradation:

```sql
SELECT timestamp, device, interface, input_bps, output_bps,
       input_drops, output_drops, input_errors, output_errors
FROM interface_samples
WHERE input_drops > 0 OR output_drops > 0
ORDER BY id DESC;
```

Latest control-plane state:

```sql
SELECT device, reachable, bgp_established, ospf_full, eigrp_neighbors,
       dmvpn_up, ikev2_ready, cpu_5s
FROM device_samples
ORDER BY id DESC
LIMIT 9;
```
