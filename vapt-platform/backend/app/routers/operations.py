from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import AuditLog
from app.models.operations import ComplianceAssessment, MonitoringEvent, MonitoringRule, SecurityIncident
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.operations import (
    ComplianceSummaryResponse,
    ComplianceAssessmentDownloadResponse,
    ComplianceAssessmentResponse,
    AuditLogResponse,
    IncidentStatusUpdate,
    MonitoringEventCreate,
    MonitoringEventResponse,
    MonitoringRuleCreate,
    MonitoringRuleResponse,
    SecurityIncidentResponse,
    TenantCreate,
    TenantResponse,
)
from app.services.operations import (
    create_tenant,
    get_compliance_assessment_payload,
    process_monitoring_event,
    summarize_compliance,
    update_incident_status,
)
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/operations", tags=["Operations"])


@router.get("/tenants", response_model=list[TenantResponse])
def list_tenants(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    return db.query(Tenant).order_by(Tenant.created_at.desc()).all()


@router.get("/audit-logs", response_model=list[AuditLogResponse])
def list_audit_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    return db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()


@router.post("/tenants", response_model=TenantResponse)
def create_tenant_record(
    payload: TenantCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    return create_tenant(db, payload.name, payload.slug, payload.settings)


@router.get("/monitoring/rules", response_model=list[MonitoringRuleResponse])
def list_monitoring_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(MonitoringRule).order_by(MonitoringRule.created_at.desc()).all()


@router.post("/monitoring/rules", response_model=MonitoringRuleResponse)
def create_monitoring_rule(
    payload: MonitoringRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    rule = MonitoringRule(
        name=payload.name,
        event_source=payload.event_source,
        event_type=payload.event_type,
        target_match=payload.target_match,
        action=payload.action,
        tool=payload.tool,
        enabled=True,
        metadata_json=payload.metadata_json,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/monitoring/rules/{rule_id}/toggle", response_model=MonitoringRuleResponse)
def toggle_monitoring_rule(rule_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    rule = db.get(MonitoringRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Monitoring rule not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/monitoring/events", response_model=list[MonitoringEventResponse])
def list_monitoring_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(MonitoringEvent).order_by(MonitoringEvent.created_at.desc()).limit(50).all()


@router.post("/monitoring/events", response_model=MonitoringEventResponse)
def ingest_monitoring_event(
    payload: MonitoringEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    event = MonitoringEvent(
        source=payload.source,
        event_type=payload.event_type,
        target=payload.target,
        severity=payload.severity,
        status="received",
        payload=payload.payload,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return process_monitoring_event(db, event)


@router.get("/incidents", response_model=list[SecurityIncidentResponse])
def list_incidents(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(SecurityIncident).order_by(SecurityIncident.created_at.desc()).limit(50).all()


@router.post("/incidents/{incident_id}/status", response_model=SecurityIncidentResponse)
def change_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    incident = db.get(SecurityIncident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return update_incident_status(db, incident, payload.status, payload.summary)


@router.get("/compliance/summary", response_model=ComplianceSummaryResponse)
def compliance_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    return summarize_compliance(db)


@router.post("/compliance/refresh", response_model=ComplianceSummaryResponse)
def refresh_compliance(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return summarize_compliance(db)


@router.get("/compliance/assessments/{assessment_id}", response_model=ComplianceAssessmentDownloadResponse)
def compliance_assessment_detail(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    assessment = db.get(ComplianceAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return get_compliance_assessment_payload(db, assessment)


@router.get("/compliance/assessments/{assessment_id}/download")
def compliance_assessment_download(
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    assessment = db.get(ComplianceAssessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    payload = ComplianceAssessmentDownloadResponse.model_validate(get_compliance_assessment_payload(db, assessment)).model_dump(mode="json")
    return JSONResponse(
        content=payload,
        headers={
            "Content-Disposition": f'attachment; filename="{assessment.name.replace(" ", "-").lower()}-scorecard.json"'
        },
    )
