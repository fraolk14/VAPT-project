# VAPTICOM Architecture Diagram

This document provides a detailed visual architecture for the current VAPTICOM platform implementation.

## High-Level System Diagram

```mermaid
flowchart TB
    User["Security Operator<br/>Browser / Desktop Shell / Mobile Browser"] --> UI["React VAPTICOM UI<br/>Dashboard, Assets, Scans, Findings,<br/>Threat Intel, Reports, Users, AI Remediation"]
    UI --> API["FastAPI Application Layer<br/>REST API, RBAC, session auth,<br/>scan orchestration, reporting"]

    subgraph Frontend["Presentation Layer"]
        UI
    end

    subgraph Backend["Application Layer"]
        API
        Auth["Auth and Access Control<br/>JWT, MFA, SSO policy, sessions"]
        ScanOrch["Scan Orchestration<br/>launch, pause, resume, cancel,<br/>schedule, reprocess, validation"]
        Findings["Normalization and Findings Service<br/>deduplication, severity mapping,<br/>AI recommendations, ownership"]
        Threat["Threat Intelligence Service<br/>MISP OSINT enrichment,<br/>MITRE and OWASP mapping"]
        AI["AI Remediation Service<br/>NVIDIA NIM or local fallback guidance"]
        Reports["Reporting Service<br/>PDF / CSV / JSON exports,<br/>compliance summaries"]
        Ops["Operations and Posture Services<br/>shadow IT, misconfigurations,<br/>unauthorized software, attack paths"]
    end

    API --> Auth
    API --> ScanOrch
    API --> Findings
    API --> Threat
    API --> AI
    API --> Reports
    API --> Ops

    subgraph Data["State and Persistence"]
        Postgres["PostgreSQL<br/>users, groups, assets, scans,<br/>findings, schedules, sessions,<br/>audit and platform metadata"]
        Redis["Redis<br/>queue / scheduler groundwork"]
    end

    Auth --> Postgres
    ScanOrch --> Postgres
    Findings --> Postgres
    Threat --> Postgres
    Reports --> Postgres
    Ops --> Postgres
    ScanOrch --> Redis

    subgraph Engines["Security Engines and External Sources"]
        Greenbone["Greenbone / OpenVAS<br/>network and host vulnerability scans"]
        ZAP["OWASP ZAP<br/>web crawling and vulnerability scans"]
        MobSF["MobSF<br/>mobile static analysis workflow"]
        MISP["MISP OSINT Feed<br/>external threat events and references"]
        Nim["NVIDIA NIM API<br/>AI remediation, explanation,<br/>recommendations, reporting"]
    end

    ScanOrch --> Greenbone
    ScanOrch --> ZAP
    ScanOrch --> MobSF
    Threat --> MISP
    AI --> Nim

    Findings --> Threat
    Findings --> AI
    Reports --> Threat
    Ops --> Findings

    subgraph Delivery["Packaging and Runtime"]
        Docker["Docker Compose<br/>API, frontend, database, redis,<br/>security engines and supporting services"]
        Desktop["Electron Desktop Wrapper<br/>cross-platform delivery"]
    end

    UI --> Desktop
    API --> Docker
    UI --> Docker
```

## Logical Boundaries

- Presentation layer: responsive React client and desktop wrapper.
- Application layer: FastAPI routers plus service modules for auth, scans, findings, AI, reporting, and posture.
- Data layer: PostgreSQL for durable state and Redis for queue and schedule support.
- Engine layer: Greenbone, ZAP, MobSF, and MISP feed integrations.
- Intelligence layer: MITRE, OWASP, compliance mapping, and NVIDIA NIM-powered remediation assistance.

## Primary Runtime Paths

1. User logs in through the UI and receives a JWT-backed session.
2. UI loads dashboard, scans, findings, assets, users, posture, and threat summary from the FastAPI API.
3. Scan orchestration launches network, web, or mobile jobs through the corresponding engine adapters.
4. Engine results are normalized into common findings records and stored in PostgreSQL.
5. Findings are enriched with threat intelligence, compliance mapping, AI guidance, and ownership metadata.
6. Dashboard and reports render the normalized and enriched data back to the user.
