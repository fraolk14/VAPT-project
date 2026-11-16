from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.ai import (
    AIAssistRequest,
    AIAssistResponse,
    AIAnalysisEnvelope,
    AIExplanationResponse,
    AIFalsePositiveResponse,
    AIFindingRecommendation,
    AIFindingRecommendationRequest,
    AIFindingRecommendationResponse,
    AIRemediationResponse,
    AIRiskScoreResponse,
    AIStatusResponse,
    AIThreatIntelResponse,
    AIVulnerabilityInput,
)
from app.services.ai import MODEL_ONLY_ANALYSES, ai_status, generate_ai_assistance, generate_finding_recommendations, is_nim_configured, run_structured_analysis
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/ai", tags=["AI"])


def _finding_cves(finding: Finding) -> list[str]:
    import re

    meta = finding.finding_metadata or {}
    text = " ".join([str(finding.cve_id or ""), *[str(c) for c in (meta.get("cve_refs") or [])]])
    return sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", text, re.I)})


def _finding_to_ai_input(finding: Finding, scan: Scan | None, db: Session | None = None) -> AIVulnerabilityInput:
    """Build model input from facts only: asset exposure from inventory, exploitation from CISA KEV."""
    from app.models.asset import Asset
    from app.services.intel import kev_catalog

    metadata = finding.finding_metadata or {}
    target = metadata.get("url") or metadata.get("host") or metadata.get("file") or (scan.target if scan else "")
    asset = db.get(Asset, finding.asset_id) if (db is not None and finding.asset_id) else None
    asset_type = asset.asset_type if asset and asset.asset_type else (
        "Web Application" if finding.source in {"zap", "web", "nuclei", "testssl"} else "Mobile Application" if finding.source == "mobsf" else "Host / Service")
    exposure = (asset.exposure or "internal").capitalize() if asset else "Unknown"
    criticality = (asset.criticality or "Medium").capitalize() if asset else "Unknown"
    cves = _finding_cves(finding)
    kev = kev_catalog()["by_cve"] if cves else {}
    in_kev = any(c in kev for c in cves)
    scan_details = " | ".join(part for part in [finding.evidence, finding.remediation, target, metadata.get("reference"), metadata.get("attack")] if part)
    return AIVulnerabilityInput(
        cve=", ".join(cves) or None,
        cvss=finding.cvss_score,
        asset={"criticality": criticality, "type": asset_type, "exposure": exposure},
        vulnerability=finding.title or "Vulnerability",
        scan_details=scan_details,
        # True only when CISA lists the CVE as exploited in the wild; None means "not known", not "no".
        exploit_available=True if in_kev else None,
        source=finding.source,
        references=[item for item in [*cves, metadata.get("reference")] if item],
    )


def _analysis_response(
    db: Session,
    *,
    current_user: User,
    analysis_type: str,
    payload: AIVulnerabilityInput,
) -> AIAnalysisEnvelope:
    enforce_roles(current_user, "admin", "analyst", "viewer")
    if analysis_type in MODEL_ONLY_ANALYSES and not is_nim_configured():
        raise HTTPException(
            status_code=409,
            detail="This analysis needs an AI model (set NVIDIA_NIM_API_KEY). Without one it would only be a guess, so it isn't offered.",
        )
    try:
        provider, model, cached, data = run_structured_analysis(
            db,
            actor=current_user.username,
            analysis_type=analysis_type,
            request=payload,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=429 if "rate limit" in str(exc).lower() else 503, detail=str(exc)) from exc
    return AIAnalysisEnvelope(
        provider=provider,
        model=model,
        cached=cached,
        analysis_type=analysis_type,
        data=data,
    )


@router.get("/status", response_model=AIStatusResponse)
def read_ai_status(
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    return AIStatusResponse.model_validate(ai_status())


@router.post("/risk-score", response_model=AIAnalysisEnvelope)
def ai_risk_score(
    payload: AIVulnerabilityInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    response = _analysis_response(db, current_user=current_user, analysis_type="risk-score", payload=payload)
    AIRiskScoreResponse.model_validate(response.data)
    return response


@router.post("/explain", response_model=AIAnalysisEnvelope)
def ai_explain(
    payload: AIVulnerabilityInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    response = _analysis_response(db, current_user=current_user, analysis_type="explain", payload=payload)
    AIExplanationResponse.model_validate(response.data)
    return response


@router.post("/remediation", response_model=AIAnalysisEnvelope)
def ai_remediation(
    payload: AIVulnerabilityInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    response = _analysis_response(db, current_user=current_user, analysis_type="remediation", payload=payload)
    AIRemediationResponse.model_validate(response.data)
    return response


@router.post("/false-positive", response_model=AIAnalysisEnvelope)
def ai_false_positive(
    payload: AIVulnerabilityInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    response = _analysis_response(db, current_user=current_user, analysis_type="false-positive", payload=payload)
    AIFalsePositiveResponse.model_validate(response.data)
    return response


@router.post("/threat-intel", response_model=AIAnalysisEnvelope)
def ai_threat_intel(
    payload: AIVulnerabilityInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    response = _analysis_response(db, current_user=current_user, analysis_type="threat-intel", payload=payload)
    AIThreatIntelResponse.model_validate(response.data)
    return response


@router.post("/assist", response_model=AIAssistResponse)
def ai_assist(
    payload: AIAssistRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    findings = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all() if payload.finding_ids else []
    scans = db.query(Scan).all()
    scan_map = {str(scan.id): scan for scan in scans}
    try:
        provider, model, content = generate_ai_assistance(payload.mode, payload.prompt or "", findings, scan_map, payload.context)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return AIAssistResponse(mode=payload.mode, content=content, model=model, provider=provider)


@router.post("/finding-recommendations", response_model=AIFindingRecommendationResponse)
def ai_finding_recommendations(
    payload: AIFindingRecommendationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    findings = db.query(Finding).filter(Finding.id.in_(payload.finding_ids)).all()
    scans = db.query(Scan).all()
    scan_map = {str(scan.id): scan for scan in scans}
    try:
        provider, model, items = generate_finding_recommendations(findings, scan_map)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return AIFindingRecommendationResponse(
        model=model,
        provider=provider,
        items=[AIFindingRecommendation.model_validate(item) for item in items],
    )


@router.get("/finding-context/{finding_id}")
def ai_finding_context(finding_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Facts for remediating one finding: scanner guidance, CISA KEV / EPSS, asset, siblings and triage history."""
    import uuid
    from collections import Counter

    from app.models.asset import Asset
    from app.services.analytics import _target_of
    from app.services.intel import epss_scores, kev_catalog

    enforce_roles(current_user, "admin", "analyst", "viewer")
    try:
        finding = db.get(Finding, uuid.UUID(finding_id))
    except ValueError:
        finding = None
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = db.get(Scan, finding.scan_id) if finding.scan_id else None
    asset = db.get(Asset, finding.asset_id) if finding.asset_id else None
    asset_names = {str(asset.id): (asset.hostname or asset.ip_address or "")} if asset else {}
    scan_targets = {str(scan.id): scan.target} if scan else {}

    cves = _finding_cves(finding)
    kev = kev_catalog()["by_cve"]
    scores = epss_scores(cves) if cves else {}
    cve_facts = []
    for c in cves:
        k = kev.get(c)
        e = scores.get(c) or {}
        cve_facts.append({
            "cve": c,
            "kev": {"name": k.get("vulnerabilityName"), "date_added": k.get("dateAdded"), "due_date": k.get("dueDate"),
                    "action": k.get("requiredAction"), "ransomware": str(k.get("knownRansomwareCampaignUse", "")).lower() == "known"} if k else None,
            "epss": e.get("epss"),
            "epss_percentile": e.get("percentile"),
        })

    same = db.query(Finding).filter(Finding.title == finding.title).all()
    statuses = Counter(str(f.status or "open").lower() for f in same)
    triaged = statuses.get("false_positive", 0) + statuses.get("resolved", 0) + statuses.get("closed", 0) + statuses.get("accepted_risk", 0)
    open_targets = sorted({_target_of(f, {}, {}) for f in same if str(f.status or "open").lower() in {"open", "in_progress"}} - {"unknown"})
    meta = finding.finding_metadata or {}
    return {
        "finding": {
            "id": str(finding.id), "title": finding.title, "severity": finding.severity, "cvss": finding.cvss_score,
            "status": finding.status, "source": finding.source, "category": finding.category,
            "target": _target_of(finding, asset_names, scan_targets), "port": finding.port, "service": finding.service,
            "evidence": (finding.evidence or "")[:2000], "remediation": finding.remediation,
            "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
            "assigned_to": finding.assigned_to, "url": meta.get("url"), "cwe": meta.get("cwe_id"),
            "possible_cves": meta.get("possible_cves") or [], "compliance": finding.compliance_map or [],
        },
        "asset": {"id": str(asset.id), "name": asset.asset_name, "exposure": asset.exposure, "criticality": asset.criticality,
                  "owner": asset.owner, "environment": asset.environment, "os": asset.os or asset.os_type} if asset else None,
        "cves": cve_facts,
        "same_issue": {
            "total": len(same),
            "open_targets": open_targets[:20],
            "open_target_count": len(open_targets),
            "false_positive": statuses.get("false_positive", 0),
            "resolved": statuses.get("resolved", 0) + statuses.get("closed", 0),
            "triaged": triaged,
        },
        "ai": ai_status(),
    }


@router.post("/finding/{finding_id}/{analysis_type}", response_model=AIAnalysisEnvelope)
def ai_analyse_finding(
    finding_id: str,
    analysis_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Run one analysis on a stored finding, with input built server-side from real facts."""
    import uuid

    if analysis_type not in {"risk-score", "explain", "remediation", "false-positive", "threat-intel"}:
        raise HTTPException(status_code=404, detail="Unknown analysis type")
    try:
        finding = db.get(Finding, uuid.UUID(finding_id))
    except ValueError:
        finding = None
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan = db.get(Scan, finding.scan_id) if finding.scan_id else None
    return _analysis_response(db, current_user=current_user, analysis_type=analysis_type,
                              payload=_finding_to_ai_input(finding, scan, db))
