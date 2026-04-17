from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse

import requests
from sqlalchemy.orm import Session

from app.models.alert import AlertEvent, AlertRule
from app.models.finding import Finding
from app.services.mail import send_email

SEVERITY_WEIGHT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def create_alert_rule(db: Session, rule: AlertRule) -> AlertRule:
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def should_fire(rule: AlertRule, finding: Finding) -> bool:
    severity = (finding.severity or "info").lower()
    min_severity = (rule.min_severity or "high").lower()
    tool_match = not rule.scan_tool or rule.scan_tool == finding.source
    return tool_match and SEVERITY_WEIGHT.get(severity, 0) >= SEVERITY_WEIGHT.get(min_severity, 0)


def _alert_body(event: AlertEvent) -> str:
    payload = event.payload or {}
    return (
        f"{payload.get('message') or 'VAPTICOM security alert'}\n\n"
        f"Finding: {payload.get('finding_title') or 'n/a'}\n"
        f"Severity: {payload.get('severity') or 'n/a'}\n"
        f"Source: {payload.get('source') or 'n/a'}\n"
        f"Assigned to: {payload.get('assigned_to') or 'Unassigned'}\n"
        f"Finding ID: {event.finding_id or 'n/a'}\n"
    )


def _validate_webhook_destination(destination: str) -> str:
    parsed = urlparse(destination)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Webhook destination must be an HTTP or HTTPS URL.")
    return destination


def deliver_alert_event(db: Session, event: AlertEvent) -> AlertEvent:
    """Deliver a queued alert event and persist the delivery outcome."""
    try:
        channel = (event.channel or "").lower()
        if channel == "email":
            send_email(
                to_address=event.destination,
                subject=f"VAPTICOM alert: {(event.payload or {}).get('finding_title') or event.rule_name}",
                body=_alert_body(event),
            )
            event.status = "sent"
            event.response_message = "Email accepted by configured SMTP gateway."
        elif channel == "webhook":
            response = requests.post(
                _validate_webhook_destination(event.destination),
                json={
                    "rule_name": event.rule_name,
                    "finding_id": event.finding_id,
                    "payload": event.payload or {},
                    "created_at": event.created_at.isoformat() if event.created_at else None,
                },
                timeout=15,
            )
            response.raise_for_status()
            event.status = "sent"
            event.response_message = f"Webhook delivered with HTTP {response.status_code}."
        else:
            raise RuntimeError(f"Unsupported alert channel '{event.channel}'.")
    except Exception as exc:
        event.status = "failed"
        event.response_message = str(exc)
    db.commit()
    db.refresh(event)
    return event


def queue_alert_events(db: Session, finding: Finding, rules: Iterable[AlertRule]) -> list[AlertEvent]:
    events: list[AlertEvent] = []
    for rule in rules:
        if not rule.enabled or not should_fire(rule, finding):
            continue
        message = (
            f"[{finding.severity or 'info'}] {finding.title} on {finding.source} "
            f"(CVE: {finding.cve_id or 'n/a'})"
        )
        event = AlertEvent(
            rule_name=rule.name,
            channel=rule.channel,
            destination=rule.destination,
            finding_id=str(finding.id),
            status="queued",
            payload={
                "message": message,
                "finding_title": finding.title,
                "severity": finding.severity,
                "source": finding.source,
                "assigned_to": finding.assigned_to,
            },
            response_message=f"Queued for {rule.channel} delivery",
        )
        db.add(event)
        events.append(event)
    db.commit()
    for event in events:
        db.refresh(event)
        deliver_alert_event(db, event)
    return events
