from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.operations import MonitoringEvent, SecurityIncident
from app.models.scan import Scan
from app.schemas.threat_intelligence import AttackMapResponse, ThreatIntelFeedResponse, ThreatIntelSummary
from app.services.threat_intelligence import (
    build_attack_map_data,
    build_threat_feed,
    fetch_misp_events,
    filter_threat_feed,
    threat_intel_summary,
)

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


@router.get("/summary", response_model=ThreatIntelSummary)
def get_threat_intelligence_summary(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    scan_map = {str(scan.id): scan for scan in scans}
    feed = build_threat_feed(findings, scan_map)
    misp_status, misp_events = fetch_misp_events()
    return ThreatIntelSummary(**threat_intel_summary(feed), misp_status=misp_status, misp_events=misp_events)


@router.get("/feed", response_model=ThreatIntelFeedResponse)
def get_threat_intelligence_feed(
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    exploited_only: bool = Query(default=False),
    db: Session = Depends(get_db),
):
    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    scan_map = {str(scan.id): scan for scan in scans}
    feed = build_threat_feed(findings, scan_map)
    filtered_feed = filter_threat_feed(feed, severity=severity, source=source, exploited_only=exploited_only)
    return ThreatIntelFeedResponse(total=len(filtered_feed), items=filtered_feed)


@router.get("/attack-map", response_model=AttackMapResponse)
def get_attack_map_data(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    assets = db.query(Asset).all()
    monitoring_events = db.query(MonitoringEvent).all()
    incidents = db.query(SecurityIncident).all()
    _, misp_events = fetch_misp_events(limit=100)
    return AttackMapResponse(
        **build_attack_map_data(
            findings=findings,
            scans=scans,
            assets=assets,
            monitoring_events=monitoring_events,
            incidents=incidents,
            misp_events=misp_events,
        )
    )
