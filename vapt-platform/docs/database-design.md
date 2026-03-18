# Database Schema

## Core tables

- `users`: local and federated identities with RBAC role, MFA flag, auth source, and lifecycle state.
- `assets`: discovered hosts, applications, mobile artifacts, and software inventory with ownership and business context.
- `scans`: normalized execution metadata for OpenVAS, ZAP, and MobSF jobs, including progress, target, schedule, and result summary.
- `scan_targets`: many-to-one mapping of scans to assets or ad hoc targets.
- `vulnerabilities`: normalized CVE catalog enriched with CVSS, remediation, compliance tags, and MITRE ATT&CK references.
- `findings`: scanner output mapped back to scans, assets, vulnerabilities, evidence, remediation, confidence, and compliance metadata.
- `audit_logs`: immutable action trail for authentication, scan execution, export activity, and administrative changes.

## Relationship flow

```text
users 1---* scans
assets 1---* scan_targets
scans 1---* scan_targets
scans 1---* findings
assets 1---* findings
vulnerabilities 1---* findings
users 1---* audit_logs
```

## Recommended production additions

- Partition `findings` and `audit_logs` by month for scale.
- Store raw scanner payloads in object storage and index summaries in PostgreSQL.
- Mirror scan telemetry and logs into Elasticsearch for fast search and timeline analysis.
- Encrypt stored scan credentials with a KMS-backed envelope key.
