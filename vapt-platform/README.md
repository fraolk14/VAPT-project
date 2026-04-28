# VAPTICOM Platform

Unified VAPT platform for network, web, mobile, threat intelligence, asset governance, misconfiguration review, and AI-assisted remediation workflows.

This repository has moved beyond a scaffold. The current version includes a working FastAPI backend, React analyst UI, Docker-based local deployment, background scan orchestration, reporting, user/group administration, a global attack map, and Gemini-assisted remediation workflows.

## Current status

Implemented and actively wired into the platform:

- Network assessment workflow for IPs, FQDNs, and IPv4 CIDR blocks up to `/24`
- Web application assessment workflow
- Mobile assessment workflow scaffold and MobSF integration path
- Background scan orchestration with queue-style lifecycle controls
- Findings normalization, CVE enrichment, MITRE ATT&CK mapping, and dashboard correlation
- Asset inventory, scan history, findings management, and hosts view
- Threat intelligence and global attack-map visualization
- User/group administration, RBAC, MFA/SSO management surfaces, and email gateway integration
- AI remediation workspace with Gemini-backed guidance flow
- Exportable reports in PDF, CSV, and JSON formats

Still evolving:

- Deep benchmark-driven hardening coverage across all products/versions
- Full exploitation-centric pentest operator workflows
- More advanced desktop packaging polish
- Additional scanner/feed depth and wider validation coverage

## Architecture snapshot

### Backend

- FastAPI API service
- PostgreSQL for primary relational storage
- Redis for orchestration/state support
- Optional Elasticsearch and Kibana profile
- Scanner/tool integrations for ZAP, MobSF, Greenbone/OpenVAS-adjacent workflows, and vulnerability correlation sources

### Frontend

- React-based web UI
- Responsive navigation and role-aware pages
- Dashboard, attack map, findings, hosts, assets, reports, AI remediation, users, threat intelligence, shadow IT, misconfigurations, and unauthorized software views

### Desktop

- Electron wrapper scaffold under [desktop](/C:/Users/User/Documents/VAPT%20project/vapt-platform/desktop)

## Main features

### Assessment workflows

- Network scans for single hosts, FQDNs, and network blocks
- Web scans for HTTP/HTTPS targets
- Mobile assessment path for APK/IPA/AAB workflows
- Pause, resume, cancel, schedule, and re-scan controls

### Findings and correlation

- Normalized findings across scanners
- CVE and severity enrichment
- MITRE ATT&CK mapping
- Asset-linked findings
- Search and filtering by target, tab, and finding content

### Threat intelligence

- Threat enrichment pipeline
- Global attack map with country drill-downs
- Source/destination country filtering
- Operational attack visualization for dashboarding and demos

### Governance and operations

- Asset inventory with manual asset creation
- Hosts page for completed scanned targets
- Shadow IT, misconfiguration, and unauthorized software views
- User/group administration and assignment workflows
- Audit-oriented reporting surfaces

### AI

- Gemini-backed AI remediation workflow
- Structured vulnerability explanation and recommendation surfaces
- AI recommendation support in findings workflows

## Repository layout

```text
vapt-platform/
├─ backend/
│  └─ app/
├─ desktop/
├─ docker/
├─ docs/
├─ frontend/
│  └─ vapt-ui/
├─ docker-compose.yml
├─ .env.example
└─ README.md
```

## Quick start

### 1. Configure environment

Copy [`.env.example`](/C:/Users/User/Documents/VAPT%20project/vapt-platform/.env.example) to `.env` and replace all demo/default secrets before using the platform outside a throwaway environment.

### 2. Start the platform

```bash
docker compose up --build
```

Default exposed services:

- UI: [http://localhost:5173](http://localhost:5173)
- API: [http://localhost:8000](http://localhost:8000)
- Mailpit UI: [http://localhost:8025](http://localhost:8025)

### 3. Optional extended profile

To include Elasticsearch, Kibana, ZAP, and MobSF from the same compose stack:

```bash
docker compose --profile extended up --build
```

## Greenbone / OpenVAS note

Greenbone is expected to run separately through the dedicated compose file under `docker/`.

```bash
docker compose -f docker/openvas-compose.yml up -d
```

See [openvas-setup.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/openvas-setup.md) for details.

## Default local admin

Bootstrap/default local admin in the current code path:

- Username: `admin`
- Password: `Admin@123`

Change this immediately in any non-demo environment.

## Reports

The platform currently supports:

- PDF export
- CSV export
- JSON export
- Compliance scorecard export

The reporting area is intended to become one of the strongest communication surfaces in the platform, so it should keep growing in narrative quality, remediation detail, reference linking, and stakeholder-specific presentation.

## Documentation

Available design and implementation docs:

- [architecture.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/architecture.md)
- [architecture-diagram.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/architecture-diagram.md)
- [how-it-works.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/how-it-works.md)
- [api-design.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/api-design.md)
- [database-design.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/database-design.md)
- [deployment-guide.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/deployment-guide.md)
- [security-best-practices.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/security-best-practices.md)
- [ai-service.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/ai-service.md)
- [vulnerability-correlation.md](/C:/Users/User/Documents/VAPT%20project/vapt-platform/docs/vulnerability-correlation.md)

## Security notes

- Do not keep production secrets in source control
- Review what vulnerability context is sent to external AI providers before enabling AI features in sensitive environments
- Prefer multi-source enrichment rather than relying on any single public vulnerability feed
- Treat exported reports as sensitive artifacts

## Suggested positioning

At its current maturity, the platform is strongest as a unified vulnerability assessment, enrichment, remediation, and security-operations workspace. It includes pentest-adjacent workflows, but if you are presenting it formally, it is safer and more accurate to describe it as:

`A unified VAPT and security validation platform with multi-engine assessment, enrichment, reporting, and AI-assisted remediation.`
