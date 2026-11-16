from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.misconfiguration import MisconfigAsset, Misconfiguration, ScanJob
from app.services.misconfig_posture import build_posture
from app.services.misconfig_scanner import fabricated_filter
from app.services.security import require_analyst

router = APIRouter(prefix="/misconfig", tags=["Misconfigurations Engine"])


class ScanJobCreate(BaseModel):
    scope: str
    organization_name: str | None = None


@router.post("/scan", dependencies=[Depends(require_analyst)])
@router.post("/v1/scan", dependencies=[Depends(require_analyst)])
def trigger_misconfig_scan(payload: ScanJobCreate):
    # The old engine here wrote a fixed list of issues for every target without probing it.
    # Configuration checks now come from the real network and web engines.
    raise HTTPException(
        status_code=410,
        detail="This endpoint has been retired. Start a real check with POST /scans/network (IP, host or CIDR) or POST /scans/web (URL); configuration issues they find appear in GET /misconfig/posture.",
    )


@router.get("/posture")
@router.get("/v1/posture")
def misconfiguration_posture(db: Session = Depends(get_db)):
    """Configuration issues found by the network, web and endpoint-agent engines, grouped by control family."""
    return build_posture(db)


@router.get("/scan/{job_id}")
@router.get("/v1/scan/{job_id}")
def get_scan_job_status(job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    assets = db.query(MisconfigAsset).filter(MisconfigAsset.scan_job_id == job.id).all()
    asset_ids = [a.id for a in assets]
    misconfigs = (
        db.query(Misconfiguration).filter(Misconfiguration.asset_id.in_(asset_ids), fabricated_filter(Misconfiguration)).all()
        if asset_ids else []
    )

    return {
        "id": job.id,
        "scope": job.scope,
        "scope_type": job.scope_type,
        "status": job.status,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "summary": {
            "total_assets": len(assets),
            "total_misconfigurations": len(misconfigs),
            "critical_count": len([m for m in misconfigs if m.severity == "CRITICAL"]),
            "high_count": len([m for m in misconfigs if m.severity == "HIGH"]),
            "medium_count": len([m for m in misconfigs if m.severity == "MEDIUM"]),
            "low_count": len([m for m in misconfigs if m.severity == "LOW"]),
        },
        "assets": [
            {
                "id": a.id,
                "ip": a.ip,
                "hostname": a.hostname,
                "asset_type": a.asset_type,
                "os_type": a.os_type,
                "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
            }
            for a in assets
        ],
        "misconfigurations": [
            {
                "id": m.id,
                "asset_id": m.asset_id,
                "issue": m.issue,
                "severity": m.severity,
                "cve": m.cve,
                "detected_by": m.detected_by,
                "remediation": m.remediation,
                "status": m.status,
                "discovered_at": m.discovered_at.isoformat() if m.discovered_at else None,
            }
            for m in misconfigs
        ],
    }


@router.get("/list")
@router.get("/v1/list")
def list_misconfigurations(db: Session = Depends(get_db)):
    misconfigs = (
        db.query(Misconfiguration)
        .filter(fabricated_filter(Misconfiguration))
        .order_by(Misconfiguration.discovered_at.desc())
        .limit(200)
        .all()
    )
    results = []
    for m in misconfigs:
        asset = db.get(MisconfigAsset, m.asset_id)
        results.append({
            "id": m.id,
            "asset_id": m.asset_id,
            "target": (asset.hostname or asset.ip) if asset else "Unknown",
            "ip": asset.ip if asset else None,
            "hostname": asset.hostname if asset else None,
            "asset_type": asset.asset_type if asset else None,
            "os_type": asset.os_type if asset else None,
            "issue": m.issue,
            "severity": m.severity.lower(),
            "cve": m.cve,
            "detected_by": m.detected_by,
            "remediation": m.remediation,
            "status": m.status,
            "discovered_at": m.discovered_at.isoformat() if m.discovered_at else None,
        })
    return results
