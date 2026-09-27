# AegisNet-WM Production Operations

## Deployment modes

AegisNet has two deliberately separate production modes.

### Production advisory

The platform, telemetry, current-state detector, OOD guard, real-data world
model, calibrated public-data consensus, audit chain, and operator UI are live.
Forecasts may create `WATCH`/advisory evidence only when telemetry is healthy,
the input is in-domain, history is complete, and every loaded artifact passes
integrity verification. Automated attack authority remains disabled.

### Production authority

This mode additionally requires the binary present-state detector to pass the
independent local acceptance gate. The policy flag
`current_detector_authority_enabled` must never be enabled merely because a
model looks good in a demo. `tools/production_readiness.py` is the release gate.

## Startup

```powershell
D:\deep\python.exe .\ops\manage_stack.py start
```

Health surfaces are loopback-only:

- `http://127.0.0.1:8510/healthz` — process/database health.
- `http://127.0.0.1:8510/readyz` — readiness for live ingestion/inference.
- `http://127.0.0.1:8510/metrics` — Prometheus-compatible core metrics.

The operator UI remains on `http://127.0.0.1:8501` and the held-out replay
demo can run separately on port 8502.

## Fail-closed rules

Operator advisories are withheld when any of the following is true:

- telemetry heartbeat is stale or polling errors exceed policy;
- temporal history is incomplete;
- the state is outside the pinned local EVE OOD envelope;
- a model artifact manifest fails SHA-256 verification;
- the pinned OOD profile SHA-256 does not match policy;
- the current detector abstains or lacks confidence;
- the authority promotion gate has not passed.

No public-data model, EVE calibration model, or next-stage model can directly
change the authoritative operator state.

## Release gate

```powershell
D:\deep\python.exe .\tools\backup_runtime.py
D:\deep\python.exe .\tools\production_readiness.py --run-tests
```

For a production-advisory deployment require:

- `platform_ready = true`
- `predictive_advisory_ready = true`
- `production_advisory_release_ready = true`
- 100% artifact/OOD integrity
- clean regression suite
- source commit recorded
- rollback backup present

Production authority additionally requires
`automated_alert_authority_ready = true`.

The current authority challenger is `aegis-binary-v6-temporal-authority`. It
uses three non-overlapping 10-second EVE state vectors (30 seconds total) and
is evaluated only against the exact locked campaign `authority-acceptance-v2`.
The live service independently verifies that the acceptance report names both
the configured artifact and configured campaign before it can honor an
authority-enable flag.

## Release freeze

After tests and readiness pass, commit the working tree and create a release:

```powershell
git status
git commit -am "release: production advisory"
D:\deep\python.exe .\tools\create_release.py --name aegisnet-prod-advisory-v1
```

The release manifest records the exact git commit, production-policy hash,
artifact directory hashes, readiness state, and rollback reference.

## Backups and rollback

`tools/backup_runtime.py` uses SQLite's online backup API, so telemetry can stay
live during a backup. Backups include the database, production policy, runtime
status, decision state, and evidence/demo summaries, each with SHA-256.

If a release misbehaves:

1. stop analysis;
2. checkout the release manifest's recorded previous git commit;
3. restore the recorded policy/model artifact set;
4. verify all artifact manifests and the OOD profile hash;
5. restore the SQLite backup only if data corruption occurred;
6. run `production_readiness.py --run-tests` before restarting analysis.

## Model lifecycle

Model directories are immutable deployment artifacts. Binary model files are
not committed to source control; metadata and SHA-256 manifests are. New models
enter as challengers, are validated against run/campaign-disjoint local data,
and become advisory champions only after acceptance. Alert authority is a
separate explicit promotion step.
