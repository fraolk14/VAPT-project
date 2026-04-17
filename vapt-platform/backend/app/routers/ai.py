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
from app.services.ai import ai_status, generate_ai_assistance, generate_finding_recommendations, run_structured_analysis
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/ai", tags=["AI"])


def _finding_to_ai_input(finding: Finding, scan: Scan | None) -> AIVulnerabilityInput:
    metadata = finding.finding_metadata or {}
    target = metadata.get("url") or metadata.get("host") or metadata.get("file") or (scan.target if scan else "")
    asset_type = (
        "Web Application"
        if finding.source == "zap"
        else "Host / Service"
        if finding.source == "openvas"
        else "Mobile Application"
        if finding.source == "mobsf"
        else "Unknown"
    )
    exposure = "External" if finding.source in {"zap", "openvas"} else "Internal"
    criticality = (
        "Critical"
        if (finding.severity or "").lower() == "critical"
        else "High"
        if (finding.severity or "").lower() == "high"
        else "Medium"
    )
    cve_refs = metadata.get("cve_refs") or []
    scan_details = " | ".join(
        part
        for part in [
            finding.evidence,
            finding.remediation,
            target,
            metadata.get("reference"),
            metadata.get("attack"),
        ]
        if part
    )
    return AIVulnerabilityInput(
        cve=finding.cve_id or (", ".join(cve_refs) if cve_refs else None),
        cvss=finding.cvss_score,
        asset={
            "criticality": criticality,
            "type": asset_type,
            "exposure": exposure,
        },
        vulnerability=finding.title or "Vulnerability",
        scan_details=scan_details,
        exploit_available=(finding.severity or "").lower() in {"critical", "high"},
        source=finding.source,
        references=[item for item in [finding.cve_id, *cve_refs, metadata.get("reference")] if item],
    )


def _analysis_response(
    db: Session,
    *,
    current_user: User,
    analysis_type: str,
    payload: AIVulnerabilityInput,
) -> AIAnalysisEnvelope:
    enforce_roles(current_user, "admin", "analyst", "viewer")
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
