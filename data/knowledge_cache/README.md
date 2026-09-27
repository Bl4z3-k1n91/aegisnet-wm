# Offline threat-knowledge cache

AegisNet never fabricates CAPEC/CVE associations. Optional local JSON files can be placed here:

- `capec_by_attack.json`: object keyed by MITRE technique ID, each value a list of CAPEC records.
- `cve_by_asset.json`: object keyed by asset/site name (`BR1`, `BR2`, `HUB`, `DC`), each value a list of locally validated CVE records.

Example CAPEC record:

```json
{"id":"CAPEC-000","name":"Example only","source":"local-curated"}
```

Example CVE record:

```json
{"id":"CVE-YYYY-NNNN","cvss":8.1,"asset":"DC","source":"local-vulnerability-scan"}
```

If these files are absent, forecast enrichment explicitly reports `cache_missing` and returns no CAPEC/CVE claims.
