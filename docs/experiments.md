# Labelled Fault Experiments

`experiments/scenario_runner.py` turns reversible EVE faults into labelled
training windows in `outputs/telemetry.db`. It keeps endpoint traffic running,
records baseline/fault/recovery boundaries, restores the fault in a `finally`
block and verifies BR1-to-DC recovery before declaring a run complete.

## Run a Scenario

Start telemetry with a 5–10 second polling interval:

```powershell
& 'D:\deep\python.exe' .\telemetry\manage_telemetry.py start -- `
  --bind 192.168.58.1 `
  --poll-interval 5

$env:EVE_PASSWORD = 'eve'
& 'D:\deep\python.exe' .\experiments\scenario_runner.py jitter `
  --baseline-seconds 30 `
  --fault-seconds 60 `
  --recovery-seconds 45
Remove-Item Env:EVE_PASSWORD
```

Supported scenarios are `jitter`, `loss-burst`, `mpls-outage`,
`internet-outage`, `core-failure`, `policy-drift`, `bgp-flap` and
`progressive-congestion`.

The runner refuses to start if the telemetry PID is dead, its heartbeat is
stale or it reports a fatal error. Static faults and progressive congestion
are always restored. The BGP flap worker also removes the neighbor shutdown
before closing its console.

## Scenario Tables

- `scenario_runs`: scenario, parameters, status and error.
- `scenario_phases`: exact UTC boundaries and class label for every phase.
- `feature_windows`: one feature vector per device and completed phase.

Each feature vector combines transport-specific IP SLA RTT/failures,
interface rates/drops/errors, NetFlow volume, syslog warnings, CPU,
reachability and minimum BGP/OSPF/EIGRP/DMVPN/IKEv2 state.

Example:

```sql
SELECT run_id, phase, label, device,
       sla_mpls_rtt_avg, sla_inet_rtt_avg,
       sla_mpls_failures, input_drop_delta,
       flow_bytes, reachable_ratio, dmvpn_min
FROM feature_windows
WHERE run_id = 1
ORDER BY id;
```

## Recovery Audit

After every live experiment, independently verify the restored topology:

```powershell
$env:EVE_PASSWORD = 'eve'
& 'D:\deep\python.exe' .\tools\audit_lab.py `
  --eve-url http://192.168.58.128 `
  --eve-path /RS `
  --subnet 192.168.58.0/24 `
  --output .\outputs\post-fault-audit.json
```

Do not use a failed run as a clean training example until its `error` is
reviewed. Its completed phases remain stored so interrupted experiments are
auditable rather than silently discarded.
