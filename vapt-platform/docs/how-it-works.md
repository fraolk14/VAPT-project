# How VAPTICOM Works

This document explains how the current VAPTICOM platform operates from login through scanning, enrichment, remediation, and reporting.

## 1. User Access and Session Flow

- Users authenticate through the FastAPI auth layer using username and password.
- The platform supports JWT-based sessions, MFA setup and verification, session tracking, and role-aware navigation.
- The UI only exposes privileged areas like `Users` and `Developer` when the signed-in role is allowed.

## 2. Data Loaded After Sign-In

After login, the frontend loads the main operating picture:

- dashboard summary
- assets inventory
- scans
- findings
- integrations health
- threat intelligence summary
- auth status and sessions
- users and groups for admins
- posture summaries
- attack surface and attack paths
- compliance and reporting summaries

This gives the dashboard a unified, cross-module view without making the user open each section first.

## 3. Scan Orchestration

The scan page supports three major assessment flows:

- network assessment through Greenbone / OpenVAS
- web assessment through OWASP ZAP
- mobile assessment through MobSF-style upload flow

Each scan is created in the platform first and then executed in the background. The platform tracks:

- queued
- waiting
- running
- paused
- completed
- failed
- cancelled

Operators can pause, resume, cancel, schedule, and re-run validation scans.

## 4. Findings Normalization

Raw engine output is transformed into a common finding format. This normalization step:

- standardizes severity
- preserves CVE and reference fields
- maps source-specific data into shared finding metadata
- groups duplicate findings into one row with a `duplicate_count`
- attaches scan completion time, target context, and compliance hints

This is what allows network, web, and mobile findings to be shown consistently in one operator experience.

## 5. Threat Intelligence Enrichment

The threat intelligence service enriches findings by combining platform findings with external context. In the current implementation this includes:

- MISP OSINT feed ingestion
- MITRE ATT&CK mapping
- OWASP web-risk mapping
- source reference coverage
- exploit availability and active exploitation indicators

The threat intelligence tab and dashboard widgets consume this data to show:

- latest feed events
- enriched findings
- ATT&CK technique coverage
- reference source coverage

## 6. AI Remediation and Recommendations

The AI layer supports two modes:

- NVIDIA NIM-backed analysis when `NVIDIA_NIM_API_KEY` is configured
- local fallback guidance when the key is not configured

The AI Remediation tab helps operators with:

- vulnerability explanation
- remediation recommendations
- risk explanation
- compliance guidance
- report generation
- general chat-style remediation assistance

The Findings page also uses the same AI layer to populate the `AI Recommendation` column.

## 7. Ownership and Triage

The Users area allows administrators to create:

- users
- groups
- role assignments
- finding ownership mappings

Findings can then be assigned to users and groups, marked false positive, escalated, or moved through verification states.

## 8. Dashboard and Reporting

The dashboard aggregates data from scans, findings, posture, and intelligence modules into a single operator view:

- risk score
- severity distribution
- attack activity
- OWASP Top 10
- threat feed signals
- posture summaries
- attack paths

Reports build on the same data model and provide export-ready content in PDF, CSV, and JSON-friendly workflows.

## 9. Responsive UI Model

The platform uses shared responsive panel and table styling so the same pages can work across:

- desktop browsers
- smaller laptop displays
- tablets
- mobile browsers

Large data tables collapse into stacked labeled records on smaller screens so operators do not need horizontal scrolling to read core data.

## 10. Deployment Model

The platform is designed to run through Docker Compose. The standard deployment includes:

- frontend container
- FastAPI backend container
- PostgreSQL
- Redis
- optional security engines and supporting services

This keeps development, demo, and operator environments consistent and makes it easier to promote the stack to more hardened deployment targets later.
