# API Design

## Authentication

- `POST /auth/register`: create a local user with role and email.
- `POST /auth/login`: issue JWT bearer token after local or LDAP authentication.
- `GET /auth/me`: return authenticated user profile.

## Dashboard and reporting

- `GET /dashboard/summary`: risk score, open findings, severity mix, and tool coverage.
- `GET /reports/findings.json`: export normalized findings as JSON.
- `GET /reports/findings.csv`: export normalized findings as CSV.

## Asset management

- `GET /assets`: list inventoried assets ordered by risk.
- `POST /assets`: create or ingest an asset record.

## Scan orchestration

- `GET /scans`: list scan executions and status.
- `POST /scans`: launch an OpenVAS, ZAP, or MobSF scan and normalize results.

## Findings

- `GET /findings`: list normalized findings across scanner sources.

## Integrations

- `GET /integrations/health`: return reachability and health posture for OpenVAS, ZAP, and MobSF.

## Planned production endpoints

- `POST /webhooks/scan-status`: receive async updates from workers.
- `GET /plugins`: list installed scanner plugins and connector metadata.
- `POST /shadow-it/discovery`: submit DNS or network telemetry for SaaS classification.
- `POST /software/baseline/check`: compare installed applications to an approved baseline.
- `GET /graphql`: optional federated query surface for custom reporting.
