from datetime import datetime, timezone
from itertools import chain

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.alert import AlertRule
from app.models.asset import Asset
from app.database import get_db
from app.models.finding import AuditLog, FalsePositiveRule, Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import BatchDeleteRequest, FalsePositiveRuleOut, FindingOut, FindingUpdate
from app.schemas.scan import ScanResponse
from app.services.alerts import queue_alert_events
from app.services.mail import send_finding_assignment_email
from app.services.orchestrator import create_scan, enqueue_mobsf_scan, enqueue_openvas_scan, enqueue_zap_scan
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/findings", tags=["Findings"])

SEVERITY_SORT = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _finding_target(finding: Finding, asset: Asset | None = None) -> str:
    if asset:
        if asset.hostname and asset.hostname != "unresolved-host":
            return asset.hostname
        if asset.asset_name:
            return asset.asset_name
        if asset.url:
            return asset.url
        if asset.ip_address:
            return asset.ip_address

    metadata = finding.finding_metadata or {}
    if finding.source in {"mobsf", "mobile"} or finding.category == "mobile":
        return metadata.get("file") or metadata.get("package_name") or metadata.get("stored_file_name") or ""

    return metadata.get("host") or metadata.get("url") or metadata.get("ip_address") or (asset.asset_name if asset else "")


def _display_identifier(payload: dict) -> str | None:
    cve_id = payload.get("cve_id")
    if cve_id:
        return cve_id

    metadata = payload.get("finding_metadata") or {}
    cve_refs = metadata.get("cve_refs") or []
    if cve_refs:
        return ", ".join(cve_refs)

    cwe_id = metadata.get("cwe_id")
    if cwe_id not in {None, "", "0"}:
        return f"CWE-{cwe_id}"

    plugin_id = metadata.get("plugin_id")
    if plugin_id:
        return f"Plugin {plugin_id}"
    return None


def _finding_details_text(finding: Finding) -> str:
    correlation = (finding.finding_metadata or {}).get("correlation", {})
    return correlation.get("correlation_summary") or finding.evidence or finding.remediation or "Finding requires review."


def _target_details(finding: Finding, asset: Asset | None = None) -> dict:
    metadata = finding.finding_metadata or {}
    return {
        "asset_name": asset.asset_name if asset else None,
        "asset_type": asset.asset_type if asset else None,
        "asset_os": asset.os if asset else None,
        "hostname": (asset.hostname if asset and asset.hostname != "unresolved-host" else None) or metadata.get("hostname"),
        "host": (asset.ip_address if asset else None) or metadata.get("host") or metadata.get("ip_address"),
        "url": (asset.url if asset else None) or metadata.get("url") or metadata.get("affected_url"),
        "service": finding.service,
        "port": finding.port,
        "protocol": finding.protocol,
        "state": finding.state,
        "banner": metadata.get("banner"),
        "server": metadata.get("server"),
        "technology": metadata.get("technology"),
        "generator": metadata.get("generator"),
        "os_family": metadata.get("os_family"),
        "cis_benchmark": metadata.get("cis_benchmark"),
    }


def _serialize_finding(finding: Finding, scan_finished_at, asset: Asset | None = None) -> dict:
    triage = (finding.finding_metadata or {}).get("triage", {})
    normalized_status = finding.status or "open"
    if finding.verification_state == "verified":
        normalized_status = "resolved"
    elif finding.verification_state == "scheduled" and normalized_status == "open":
        normalized_status = "in_progress"

    target_val = _finding_target(finding, asset) or (asset.asset_name if asset else None) or (asset.hostname if asset else None)

    payload = {
        **finding.__dict__,
        "target": target_val or "n/a",
        "status": normalized_status,
        "scan_finished_at": scan_finished_at,
        "duplicate_count": 1,
        "group_key": str(finding.id),
        "asset_name": asset.asset_name if asset else (asset.hostname if asset else None),
        "resolved_by": triage.get("resolved_by") or finding.assigned_to,
        "target_details": _target_details(finding, asset),
    }
    payload["display_id"] = _display_identifier(payload)
    return payload


@router.get("/", response_model=list[FindingOut])
def list_findings(db: Session = Depends(get_db)):
    rows = (
        db.query(Finding, Scan.finished_at, Asset)
        .outerjoin(Scan, Scan.id == Finding.scan_id)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .all()
    )
    grouped_findings: dict[tuple, dict] = {}
    for finding, finished_at, asset in rows:
        payload = _serialize_finding(finding, finished_at, asset)

        host_target = (
            (asset.asset_name if asset else None)
            or (asset.hostname if asset else None)
            or (payload.get("target_details", {}).get("hostname"))
            or _finding_target(finding, asset)
        ).strip().lower()

        group_key = (
            finding.source,
            finding.title.strip().lower(),
            host_target,
            finding.port or 0,
            (finding.protocol or "").lower(),
            (finding.status or "open").lower(),
        )
        existing = grouped_findings.get(group_key)
        if existing is None:
            payload["group_key"] = "|".join(str(part) for part in group_key if part not in {None, ""})
            grouped_findings[group_key] = payload
            continue

        existing["duplicate_count"] += 1
        existing["compliance_map"] = sorted(
            dict.fromkeys(chain(existing.get("compliance_map", []), payload.get("compliance_map", [])))
        )
        merged_refs = sorted(
            dict.fromkeys(
                chain(
                    (existing.get("finding_metadata") or {}).get("cve_refs", []),
                    (payload.get("finding_metadata") or {}).get("cve_refs", []),
                )
            )
        )
        existing.setdefault("finding_metadata", {})
        existing["finding_metadata"]["cve_refs"] = merged_refs
        if not existing.get("display_id") and payload.get("display_id"):
            existing["display_id"] = payload["display_id"]
        if (payload.get("cvss_score") or 0) > (existing.get("cvss_score") or 0):
            for key in [
                "severity",
                "cvss_score",
                "evidence",
                "remediation",
                "service",
                "state",
                "finding_metadata",
                "display_id",
                "cve_id",
            ]:
                existing[key] = payload.get(key)
        if payload["detected_at"] > existing["detected_at"]:
            existing["detected_at"] = payload["detected_at"]
        if payload.get("scan_finished_at") and (
            not existing.get("scan_finished_at") or payload["scan_finished_at"] > existing["scan_finished_at"]
        ):
            existing["scan_finished_at"] = payload["scan_finished_at"]

    findings = [FindingOut.model_validate(item) for item in grouped_findings.values()]
    findings.sort(
        key=lambda item: (
            SEVERITY_SORT.get((item.severity or "info").lower(), 0),
            item.duplicate_count,
            item.cvss_score or 0,
            item.detected_at,
        ),
        reverse=True,
    )
    return findings


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding_detail(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan_finished_at = db.query(Scan.finished_at).filter(Scan.id == finding.scan_id).scalar()
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    return FindingOut.model_validate(_serialize_finding(finding, scan_finished_at, asset))


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    before = {
        "status": finding.status,
        "severity": finding.severity,
        "assigned_to": finding.assigned_to,
        "team_name": finding.team_name,
        "verification_state": finding.verification_state,
    }

    if payload.mark_false_positive:
        finding.status = "false_positive"
        finding.finding_metadata = {**(finding.finding_metadata or {}), "triage": {"mark_false_positive": True}}
    elif payload.status:
        finding.status = payload.status
        if payload.status == "resolved":
            finding.resolved_at = datetime.now(timezone.utc)
            finding.finding_metadata = {
                **(finding.finding_metadata or {}),
                "triage": {
                    **((finding.finding_metadata or {}).get("triage", {})),
                    "resolved_by": finding.assigned_to or current_user.username,
                },
            }

    if payload.severity:
        finding.severity = payload.severity
        finding.finding_metadata = {
            **(finding.finding_metadata or {}),
            "triage": {
                **((finding.finding_metadata or {}).get("triage", {})),
                "manual_severity": payload.severity,
            },
        }

    if payload.assigned_to is not None:
        previous_assignee = finding.assigned_to
        finding.assigned_to = payload.assigned_to
        if payload.assigned_to and payload.assigned_to != previous_assignee:
            assigned_user = db.query(User).filter(User.username == payload.assigned_to).first()
            if assigned_user and assigned_user.email:
                try:
                    send_finding_assignment_email(
                        email=assigned_user.email,
                        username=assigned_user.username,
                        finding_title=finding.title,
                        severity=finding.severity or "info",
                        target=_finding_target(finding),
                        details=_finding_details_text(finding),
                    )
                except Exception:
                    pass
    if payload.team_name is not None:
        finding.team_name = payload.team_name
    if payload.sla_due_at is not None:
        finding.sla_due_at = payload.sla_due_at
    if payload.verification_state is not None:
        finding.verification_state = payload.verification_state
        triage = {**((finding.finding_metadata or {}).get("triage", {}))}
        if payload.verification_state == "scheduled":
            finding.status = "in_progress"
        elif payload.verification_state == "verified":
            finding.status = "resolved"
            finding.resolved_at = datetime.now(timezone.utc)
            triage["resolved_by"] = finding.assigned_to or current_user.username
        finding.finding_metadata = {
            **(finding.finding_metadata or {}),
            "triage": triage,
        }

    after = {
        "status": finding.status,
        "severity": finding.severity,
        "assigned_to": finding.assigned_to,
        "team_name": finding.team_name,
        "verification_state": finding.verification_state,
    }
    db.add(
        AuditLog(
            actor=current_user.username,
            action="finding.update",
            resource_type="finding",
            resource_id=str(finding.id),
            details={"title": finding.title, "before": before, "after": after},
        )
    )
    db.commit()
    db.refresh(finding)
    rules = db.query(AlertRule).filter(AlertRule.enabled.is_(True)).all()
    queue_alert_events(db, finding, rules)
    scan_finished_at = db.query(Scan.finished_at).filter(Scan.id == finding.scan_id).scalar()
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    return FindingOut.model_validate(_serialize_finding(finding, scan_finished_at, asset))


@router.delete("/{finding_id}", status_code=200)
def delete_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    finding = db.get(Finding, finding_id)
    if not finding:
        return {"message": "Finding already deleted", "id": finding_id}

    target_title = finding.title.strip() if finding.title else ""
    cve_id = finding.cve_id
    source = finding.source

    # Register suppression rule to prevent background scanner pollers from restoring deleted finding
    if target_title:
        existing_rule = db.query(FalsePositiveRule).filter(FalsePositiveRule.title_pattern == target_title).first()
        if not existing_rule:
            db.add(
                FalsePositiveRule(
                    title_pattern=target_title,
                    cve_id=cve_id,
                    source=source,
                    reason=f"Permanently deleted by user {current_user.username}",
                    enabled=True,
                )
            )

    # Permanently delete target finding and all duplicate rows for this title from PostgreSQL DB
    matches = db.query(Finding).filter(Finding.title.ilike(target_title)).all() if target_title else [finding]
    deleted_count = len(matches)
    for m in matches:
        db.delete(m)

    db.add(
        AuditLog(
            actor=current_user.username,
            action="finding.delete",
            resource_type="finding",
            resource_id=finding_id,
            details={"title": target_title, "deleted_count": deleted_count},
        )
    )
    db.commit()
    return {"message": f"Permanently deleted {deleted_count} finding record(s) from database", "id": finding_id}


@router.post("/batch-delete", status_code=200)
def batch_delete_findings(
    payload: BatchDeleteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    if not payload.finding_ids:
        return {"deleted_count": 0}

    target_findings = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all()
    total_deleted = 0

    for finding in target_findings:
        target_title = finding.title.strip() if finding.title else ""
        if not target_title:
            db.delete(finding)
            total_deleted += 1
            continue

        # Register suppression rule to prevent background scanner pollers from restoring deleted finding
        existing_rule = db.query(FalsePositiveRule).filter(FalsePositiveRule.title_pattern == target_title).first()
        if not existing_rule:
            db.add(
                FalsePositiveRule(
                    title_pattern=target_title,
                    cve_id=finding.cve_id,
                    source=finding.source,
                    reason=f"Permanently deleted by user {current_user.username}",
                    enabled=True,
                )
            )

        # Permanently delete all duplicate rows for this title from PostgreSQL DB
        matches = db.query(Finding).filter(Finding.title.ilike(target_title)).all()
        for m in matches:
            db.delete(m)
            total_deleted += 1

    db.add(
        AuditLog(
            actor=current_user.username,
            action="finding.batch_delete",
            resource_type="finding",
            resource_id="batch",
            details={"deleted_count": total_deleted, "ids": payload.finding_ids[:50]},
        )
    )
    db.commit()
    return {"deleted_count": total_deleted, "message": f"Permanently deleted {total_deleted} finding record(s) from database"}


@router.get("/false-positive-rules", response_model=list[FalsePositiveRuleOut])
def list_false_positive_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    return db.query(FalsePositiveRule).order_by(FalsePositiveRule.created_at.desc()).all()


@router.post("/{finding_id}/suppress-global", response_model=FalsePositiveRuleOut)
def suppress_globally(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    rule = FalsePositiveRule(
        title_pattern=finding.title,
        cve_id=finding.cve_id,
        source=finding.source,
        reason="Promoted to global false-positive from developer console.",
        enabled=True,
    )
    db.add(rule)
    similar_findings = (
        db.query(Finding)
        .filter(Finding.title == finding.title, Finding.source == finding.source)
        .all()
    )
    for item in similar_findings:
        item.status = "false_positive"
        item.finding_metadata = {
            **(item.finding_metadata or {}),
            "triage": {
                **((item.finding_metadata or {}).get("triage", {})),
                "suppressed_globally": True,
            },
        }
    db.add(
        AuditLog(
            actor=current_user.username,
            action="finding.suppress_global",
            resource_type="finding",
            resource_id=str(finding.id),
            details={"title": finding.title, "source": finding.source, "affected_findings": len(similar_findings)},
        )
    )
    db.commit()
    db.refresh(rule)
    return rule


@router.post("/{finding_id}/validate-fix", response_model=ScanResponse)
def validate_fix(
    finding_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    source_scan = db.get(Scan, finding.scan_id)
    if not source_scan:
        raise HTTPException(status_code=404, detail="Source scan not found")

    validation_scan = Scan(
        scan_name=f"Validation {source_scan.target}",
        scan_type=source_scan.scan_type,
        tool=source_scan.tool,
        target=source_scan.target,
        profile="validation",
        schedule=None,
        engine_metadata={
            "validation_for_finding_id": str(finding.id),
            "validation_for_scan_id": str(source_scan.id),
        },
        status="waiting",
        progress="0",
        error_message="Validation scan queued. A follow-up assessment will verify remediation in the background.",
        triggered_by=current_user.id,
    )
    validation_scan = create_scan(db, validation_scan)
    finding.verification_state = "scheduled"
    db.add(
        AuditLog(
            actor=current_user.username,
            action="finding.validate_fix",
            resource_type="finding",
            resource_id=str(finding.id),
            details={"validation_scan_id": str(validation_scan.id), "source_scan_id": str(source_scan.id)},
        )
    )
    db.commit()
    db.refresh(finding)

    if validation_scan.tool == "openvas":
        background_tasks.add_task(enqueue_openvas_scan, str(validation_scan.id))
    elif validation_scan.tool == "zap":
        background_tasks.add_task(enqueue_zap_scan, str(validation_scan.id))
    elif validation_scan.tool == "mobsf":
        background_tasks.add_task(enqueue_mobsf_scan, str(validation_scan.id))
    else:
        validation_scan.status = "completed"
        validation_scan.progress = "100"
        validation_scan.finished_at = datetime.now(timezone.utc)
        validation_scan.error_message = "Validation recorded. Re-run the external pipeline hook to confirm remediation from upstream tooling."
        db.commit()
        db.refresh(validation_scan)
    return validation_scan
