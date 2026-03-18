# VAPT Platform

Unified VAPT platform scaffold that combines network, web, mobile, shadow IT, and software governance workflows.

## Included

- FastAPI backend with JWT auth, LDAP bridge, RBAC, scan orchestration, reporting, and integration health endpoints
- React dashboard with responsive analyst views for risk, scans, findings, and assets
- Electron desktop wrapper scaffold
- Docker Compose topology for API, frontend, PostgreSQL, Redis, Elasticsearch, OpenVAS, ZAP, and MobSF
- Architecture, API, database, deployment, and security documentation under `docs/`

## Quick start

```bash
docker compose up --build
```

## Default demo login

- Username: `admin`
- Password: `ChangeMe123!`

Change these immediately for non-demo environments.
