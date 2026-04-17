from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.operations import (
    ComplianceAssessment,
    ComplianceTemplate,
    MonitoringEvent,
    MonitoringRule,
    SecurityIncident,
)
from app.models.scan import Scan
from app.models.tenant import Tenant
from app.services.orchestrator import create_scan, enqueue_mobsf_scan, enqueue_openvas_scan, enqueue_zap_scan


def default_tenant(db: Session) -> Tenant | None:
    return db.query(Tenant).filter(Tenant.is_default.is_(True)).first()


def create_tenant(db: Session, name: str, slug: str, settings: dict) -> Tenant:
    tenant = Tenant(name=name, slug=slug, settings=settings, is_default=False, status="active")
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


def enqueue_scan_for_tool(scan: Scan) -> None:
    if scan.tool == "openvas":
        enqueue_openvas_scan(str(scan.id))
    elif scan.tool == "zap":
        enqueue_zap_scan(str(scan.id))
    elif scan.tool == "mobsf":
        enqueue_mobsf_scan(str(scan.id))


def process_monitoring_event(db: Session, event: MonitoringEvent) -> MonitoringEvent:
    rules = db.query(MonitoringRule).filter(
        MonitoringRule.enabled.is_(True),
        MonitoringRule.event_source == event.source,
        MonitoringRule.event_type == event.event_type,
    ).all()

    for rule in rules:
        if rule.target_match and rule.target_match.lower() not in event.target.lower():
            continue
        if rule.action == "queue_scan":
            scan_type = "web" if rule.tool == "zap" else "mobile" if rule.tool == "mobsf" else "network"
            scan = Scan(
                scan_name=f"Event-triggered {event.target}",
                scan_type=scan_type,
                tool=rule.tool,
                target=event.target,
                profile="continuous-monitoring",
                schedule=None,
                status="waiting",
                progress="0",
                engine_metadata={"monitoring_event_id": str(event.id), "source": event.source},
                error_message="Event-triggered assessment queued in the background.",
            )
            scan = create_scan(db, scan)
            event.triggered_scan_id = scan.id
            event.status = "scan_queued"
            db.commit()
            db.refresh(event)
            enqueue_scan_for_tool(scan)
            break

    related_findings = db.query(Finding).filter(
        Finding.status == "open",
        Finding.severity.in_(["critical", "high"]),
    ).order_by(Finding.detected_at.desc()).limit(5).all()
    if event.severity in {"critical", "high"} or related_findings:
        incident = SecurityIncident(
            title=f"{event.source} incident on {event.target}",
            source=event.source,
            severity=event.severity,
            status="open",
            target=event.target,
            summary=f"{event.event_type} triggered correlation and follow-up investigation.",
            related_finding_ids=[str(item.id) for item in related_findings],
            metadata_json={"event_id": str(event.id), "payload": event.payload},
        )
        db.add(incident)
        event.status = "correlated"
        db.commit()
        db.refresh(event)

    return event


def ensure_compliance_templates(db: Session) -> None:
    defaults = [
        ("OWASP ASVS Baseline", "OWASP ASVS", ["Authentication", "Session Management", "Validation"]),
        ("NIST 800-53 Essentials", "NIST", ["RA-5", "SI-2", "CA-7"]),
        ("ISO 27001 Readiness", "ISO 27001", ["A.8", "A.12", "A.14"]),
    ]
    existing = {item.name for item in db.query(ComplianceTemplate).all()}
    for name, framework, controls in defaults:
        if name in existing:
            continue
        db.add(ComplianceTemplate(name=name, framework=framework, controls=controls, enabled=True))
    db.commit()


def refresh_compliance_assessments(db: Session) -> None:
    ensure_compliance_templates(db)
    findings = db.query(Finding).all()
    templates = db.query(ComplianceTemplate).filter(ComplianceTemplate.enabled.is_(True)).all()
    existing = {item.name: item for item in db.query(ComplianceAssessment).all()}

    for template in templates:
        mapped = [
            finding for finding in findings
            if template.framework in (finding.compliance_map or []) or any(control in (finding.compliance_map or []) for control in template.controls)
        ]
        score = max(0, 100 - (len(mapped) * 7))
        summary = {
            "mapped_findings": len(mapped),
            "open_findings": sum(1 for finding in mapped if finding.status == "open"),
            "last_refreshed_at": datetime.now(timezone.utc).isoformat(),
        }
        name = f"{template.framework} Continuous Assessment"
        if name in existing:
            assessment = existing[name]
            assessment.status = "active"
            assessment.score = str(score)
            assessment.summary = summary
        else:
            db.add(
                ComplianceAssessment(
                    template_id=template.id,
                    name=name,
                    status="active",
                    score=str(score),
                    summary=summary,
                )
            )
    db.commit()


def summarize_compliance(db: Session) -> dict:
    refresh_compliance_assessments(db)
    templates = db.query(ComplianceTemplate).order_by(ComplianceTemplate.created_at.desc()).all()
    assessments = db.query(ComplianceAssessment).order_by(ComplianceAssessment.created_at.desc()).all()
    findings = db.query(Finding).all()
    frameworks = Counter(
        item
        for finding in findings
        for item in (finding.compliance_map or [])
    )
    return {
        "templates": templates,
        "assessments": assessments,
        "mapped_findings": sum(1 for finding in findings if finding.compliance_map),
        "frameworks": dict(frameworks),
    }


def update_incident_status(db: Session, incident: SecurityIncident, status: str, summary: str | None = None) -> SecurityIncident:
    incident.status = status
    if summary is not None:
        incident.summary = summary
    db.commit()
    db.refresh(incident)
    return incident


def get_compliance_assessment_payload(db: Session, assessment: ComplianceAssessment) -> dict:
    template = db.query(ComplianceTemplate).filter(ComplianceTemplate.id == assessment.template_id).first()
    return {
        "assessment": assessment,
        "framework": template.framework if template else None,
        "controls": template.controls if template else [],
        "generated_at": datetime.now(timezone.utc),
    }
