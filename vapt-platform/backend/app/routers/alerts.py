from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.alert import AlertEvent, AlertRule
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.alert import AlertEventResponse, AlertRuleCreate, AlertRuleResponse, AlertRuleTestResponse
from app.services.alerts import create_alert_rule, deliver_alert_event, queue_alert_events, should_fire
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/rules", response_model=list[AlertRuleResponse])
def list_rules(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(AlertRule).order_by(AlertRule.created_at.desc()).all()


@router.post("/rules", response_model=AlertRuleResponse)
def create_rule(
    payload: AlertRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    rule = AlertRule(
        name=payload.name,
        channel=payload.channel,
        destination=payload.destination,
        min_severity=payload.min_severity,
        scan_tool=payload.scan_tool,
        enabled=True,
        metadata_json=payload.metadata_json,
    )
    return create_alert_rule(db, rule)


@router.post("/rules/{rule_id}/toggle", response_model=AlertRuleResponse)
def toggle_rule(rule_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    rule = db.get(AlertRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.get("/events", response_model=list[AlertEventResponse])
def list_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(AlertEvent).order_by(AlertEvent.created_at.desc()).limit(50).all()


@router.post("/events/{event_id}/retry", response_model=AlertEventResponse)
def retry_event(event_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    event = db.get(AlertEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Alert event not found")
    event.status = "queued"
    event.response_message = "Retry requested by operator."
    db.commit()
    db.refresh(event)
    return deliver_alert_event(db, event)


@router.post("/rules/{rule_id}/test", response_model=AlertRuleTestResponse)
def test_rule(rule_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    rule = db.get(AlertRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    finding = (
        db.query(Finding)
        .filter(Finding.status == "open")
        .order_by(Finding.detected_at.desc())
        .first()
    )

    if not finding or not should_fire(rule, finding):
        synthetic_scan = Scan(
            scan_name=f"Alert validation for {rule.name}",
            scan_type="validation",
            tool=rule.scan_tool or "platform",
            status="completed",
            target=rule.destination,
            profile="alert-validation",
            progress="100",
            result_summary={"simulated": True, "rule_id": str(rule.id)},
            engine_metadata={"source": "alert-rule-test"},
        )
        db.add(synthetic_scan)
        db.flush()
        finding = Finding(
            scan_id=synthetic_scan.id,
            title="Simulated alert validation finding",
            category="validation",
            source=rule.scan_tool or "platform",
            status="open",
            port=0,
            protocol="test",
            service="alerting",
            state="open",
            severity=rule.min_severity,
            confidence=0.95,
            evidence="Synthetic finding created to validate alert delivery.",
            remediation="Confirm the alert channel receives notifications and document the runbook.",
            compliance_map=["OWASP ASVS"],
            finding_metadata={"simulated": True, "source": "alert-rule-test"},
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

    events = queue_alert_events(db, finding, [rule])
    if not events:
        raise HTTPException(status_code=400, detail="Alert rule did not match the available finding severity or tool scope")
    event = events[0]
    return {"rule": rule, "event": event}
