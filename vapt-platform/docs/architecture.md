# System Architecture

## Text-based architecture diagram

```text
                               +-----------------------------+
                               |   Web UI / Desktop Shell    |
                               | React SPA + Electron shell  |
                               +-------------+---------------+
                                             |
                                             v
                              +--------------+---------------+
                              |        FastAPI API Gateway    |
                              | Auth, RBAC, orchestration,    |
                              | reporting, integrations       |
                              +---+---------------+-----------+
                                  |               |
                 +----------------+               +------------------+
                 |                                                   |
                 v                                                   v
     +-----------+-----------+                         +-------------+-------------+
     |  PostgreSQL           |                         | Elasticsearch + Kibana    |
     | assets, scans, users, |                         | logs, search, audit trail |
     | findings, audit logs  |                         +-------------+-------------+
     +-----------+-----------+                                       |
                 |                                                   |
                 v                                                   v
     +-----------+-----------+                         +-------------+-------------+
     | Redis / Task Queue    |                         | Scan Engines / Connectors |
     | scheduling, retries   |                         | OpenVAS, ZAP, MobSF,      |
     +-----------+-----------+                         | shadow IT, software agent  |
                 |                                     +---------------------------+
                 v
     +-----------+-----------+
     | Worker pool / Celery  |
     | long-running scans    |
     +-----------------------+
```

## Service boundaries

- `api-gateway`: authentication, RBAC, orchestration, normalization, report export, public APIs.
- `scan-workers`: execute or proxy scanner runs, poll engine status, normalize findings, and push events.
- `asset-intelligence`: asset discovery, shadow IT discovery, misconfiguration checks, software baseline comparisons.
- `reporting`: risk scoring, MITRE ATT&CK mapping, compliance overlays, and export generation.
- `desktop-shell`: Electron wrapper around the responsive web client for Windows, macOS, and Linux packaging.

## Folder structure

```text
vapt-platform/
|-- backend/
|   |-- app/
|   |   |-- config/
|   |   |-- models/
|   |   |-- routers/
|   |   |-- schemas/
|   |   `-- services/
|   |-- Dockerfile
|   `-- requirements.txt
|-- frontend/
|   `-- vapt-ui/
|       |-- src/
|       |   |-- api/
|       |   |-- components/
|       |   `-- pages/
|       `-- Dockerfile
|-- desktop/
|   `-- electron/
|-- docker/
|-- docs/
|-- .env.example
`-- docker-compose.yml
```
