from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.operations import MonitoringEvent, SecurityIncident
from app.models.scan import Scan
from app.schemas.threat_intelligence import AttackMapResponse, ThreatIntelFeedResponse, ThreatIntelSummary
from app.services.threat_intelligence import (
    build_external_event_feed,
    build_attack_map_data,
    build_threat_feed,
    fetch_abusech_events,
    fetch_urlhaus_recent,
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
    abusech_status, abusech_events = fetch_abusech_events()
    urlhaus_status, urlhaus_rows = fetch_urlhaus_recent()
    external_events = build_external_event_feed(findings, abusech_events, urlhaus_rows)
    external_status = "connected" if external_events else ("connected" if abusech_status == "connected" or urlhaus_status == "connected" else "unavailable")
    return ThreatIntelSummary(
        **threat_intel_summary(feed),
        misp_status=abusech_status,
        misp_events=abusech_events,
        external_feed_status=external_status,
        external_events=external_events,
    )


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
    _, abusech_events = fetch_abusech_events(limit=100)
    return AttackMapResponse(
        **build_attack_map_data(
            findings=findings,
            scans=scans,
            assets=assets,
            monitoring_events=monitoring_events,
            incidents=incidents,
            ti_events=abusech_events,
        )
    )


@router.get("/attack-map/data")
@router.get("/v1/attack-map/data")
def get_attack_map_dashboard(
    time_range: str = Query(default="24h"),
    db: Session = Depends(get_db)
):
    from app.services.threat_intelligence import build_attack_map_dashboard_data
    return build_attack_map_dashboard_data(db, time_range=time_range)


@router.get("/exposure")
def cve_exposure(db: Session = Depends(get_db)):
    """CVEs in open findings, prioritised by CISA KEV (exploited in the wild) and FIRST EPSS."""
    from app.services.intel import exposure

    return exposure(db)


@router.get("/kev/recent")
def kev_recent_additions(days: int = Query(default=30, ge=1, le=365), db: Session = Depends(get_db)):
    from app.services.intel import kev_recent

    return kev_recent(db, days)


@router.get("/today")
def vulnerabilities_today(kev_days: int = Query(default=3, ge=1, le=14), db: Session = Depends(get_db)):
    """Today's vulnerability news: new CISA KEV entries, Microsoft's latest release, NVD's last 24 hours."""
    from app.services.intel_today import today_feed

    return today_feed(db, kev_days)


@router.get("/lookup")
def indicator_lookup(q: str = Query(min_length=2, max_length=255), db: Session = Depends(get_db)):
    """Reputation and exposure for an IP or domain from real sources, with the verdict's reasons."""
    from app.services.intel import lookup

    return lookup(db, q)


@router.get("/sources")
def intel_sources():
    from app.services.intel import sources_status

    return sources_status()


@router.get("/live-map")
def live_threat_map(window: str = Query(default="7d", pattern="^(24h|7d|30d)$")):
    """Real global threat telemetry (DShield, Feodo Tracker, optional ThreatFox), geolocated.

    Declared before the catch-all target route below so it isn't swallowed by it.
    """
    from app.services.live_threat_map import get_live_map

    return get_live_map(window)


@router.get("/{target:path}")
def get_target_threat_intelligence(target: str, db: Session = Depends(get_db)):
    from app.services.threat_intelligence import get_target_threat_intel
    return get_target_threat_intel(db, target)
