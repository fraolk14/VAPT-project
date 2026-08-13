from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.misconfiguration import Misconfiguration, MisconfigAsset, ScanJob
from app.models.user import User
from app.schemas.asset import AssetCreate, AssetUpdate, AssetResponse, MisconfigurationBrief
from app.services.security import enforce_roles, get_current_user
from app.services.misconfig_scanner import parse_scope_type, run_misconfiguration_scan_job

router = APIRouter(prefix="/assets", tags=["Assets"])


def trigger_auto_scan(target_scope: str, db_session_factory):
    """Triggers an automatic background scan for newly registered assets."""
    db = db_session_factory()
    try:
        scope_type = parse_scope_type(target_scope)
        scan_job = ScanJob(
            scope=target_scope,
            scope_type=scope_type,
            status="PENDING",
        )
        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)
        run_misconfiguration_scan_job(scan_job.id)
    except Exception as e:
        print(f"[AutoScan] Error running background scan for asset target '{target_scope}': {e}")
    finally:
        db.close()


def _format_asset_response(a: Asset, db: Session) -> dict[str, Any]:
    conds = []
    if a.ip_address:
        conds.append(MisconfigAsset.ip == a.ip_address)
    if a.hostname:
        conds.append(MisconfigAsset.hostname == a.hostname)
    if a.asset_name and a.asset_name != a.hostname:
        conds.append(MisconfigAsset.hostname == a.asset_name)

    m_list = []
    if conds:
        from sqlalchemy import or_
        m_list = (
            db.query(Misconfiguration)
            .join(MisconfigAsset, Misconfiguration.asset_id == MisconfigAsset.id)
            .filter(or_(*conds))
            .order_by(Misconfiguration.discovered_at.desc())
            .all()
        )

    return {
        "id": a.id,
        "hostname": a.hostname or a.asset_name or a.ip_address,
        "ip_address": a.ip_address,
        "url": a.url,
        "os_type": a.os_type or a.os or "Unknown",
        "os": a.os or a.os_type or "Unknown",
        "owner": a.owner,
        "environment": a.environment or "Production",
        "criticality": a.criticality or "Medium",
        "risk_level": a.risk_level or ("High" if (a.risk_score or 0) > 70 else "Medium" if (a.risk_score or 0) > 40 else "Low"),
        "classification": a.classification or (a.exposure.capitalize() if a.exposure else "Internal"),
        "exposure": a.exposure or (a.classification.lower() if a.classification else "internal"),
        "asset_type": a.asset_type or "OS",
        "asset_name": a.asset_name or a.hostname or a.ip_address,
        "tags": a.tags or [],
        "is_active": a.is_active if a.is_active is not None else True,
        "risk_score": a.risk_score or 0.0,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
        "last_scan_id": a.last_scan_id,
        "misconfigurations_count": len(m_list),
        "misconfigurations": [
            {
                "id": m.id,
                "issue": m.issue,
                "severity": m.severity,
                "cve": m.cve,
                "detected_by": m.detected_by,
                "remediation": m.remediation,
                "status": m.status,
                "discovered_at": m.discovered_at,
            }
            for m in m_list
        ],
    }


@router.get("/", response_model=list[AssetResponse])
@router.get("/v1/", response_model=list[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    return [_format_asset_response(a, db) for a in assets]


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
@router.post("/v1/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "SecurityEngineer")

    risk_score_calc = {
        "critical": 90.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
    }.get(payload.criticality.lower(), 50.0)

    # Upsert check without deleting existing data
    existing = None
    if payload.url:
        existing = db.query(Asset).filter(Asset.url == payload.url).first()
    if not existing and payload.ip_address:
        existing = db.query(Asset).filter(Asset.ip_address == payload.ip_address).first()
    if not existing and payload.hostname:
        existing = db.query(Asset).filter(Asset.hostname == payload.hostname).first()

    if existing:
        existing.hostname = payload.hostname or existing.hostname
        existing.ip_address = payload.ip_address or existing.ip_address
        existing.url = payload.url or existing.url
        existing.os_type = payload.os_type or existing.os_type
        existing.os = payload.os or existing.os
        existing.owner = payload.owner or existing.owner
        existing.environment = payload.environment or existing.environment
        existing.criticality = payload.criticality or existing.criticality
        existing.risk_level = payload.risk_level or existing.risk_level
        existing.classification = payload.classification or existing.classification
        existing.exposure = payload.classification.lower() if payload.classification else existing.exposure
        existing.asset_type = payload.asset_type or existing.asset_type
        existing.is_active = payload.is_active
        existing.risk_score = risk_score_calc

        db.commit()
        db.refresh(existing)
        asset_obj = existing
    else:
        db_asset = Asset(
            asset_name=payload.asset_name or payload.hostname or payload.ip_address,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            url=payload.url,
            os=payload.os or payload.os_type,
            os_type=payload.os_type or payload.os,
            owner=payload.owner,
            environment=payload.environment,
            criticality=payload.criticality,
            risk_level=payload.risk_level,
            classification=payload.classification,
            exposure=payload.classification.lower() if payload.classification else "internal",
            asset_type=payload.asset_type,
            is_active=payload.is_active,
            risk_score=risk_score_calc,
        )
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)
        asset_obj = db_asset

    # INTEGRATION REQUIREMENT 4: Trigger background scan for newly registered asset
    scan_target = asset_obj.url or asset_obj.ip_address or asset_obj.hostname
    if scan_target:
        from app.database import SessionLocal
        background_tasks.add_task(trigger_auto_scan, scan_target, SessionLocal)

    return _format_asset_response(asset_obj, db)


@router.put("/{asset_id}", response_model=AssetResponse)
@router.put("/v1/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "SecurityEngineer")
    import uuid
    try:
        uid = uuid.UUID(asset_id)
        asset = db.get(Asset, uid)
    except ValueError:
        asset = db.query(Asset).filter(Asset.hostname == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if payload.hostname is not None:
        asset.hostname = payload.hostname
    if payload.ip_address is not None:
        asset.ip_address = payload.ip_address
    if payload.url is not None:
        asset.url = payload.url
    if payload.os_type is not None:
        asset.os_type = payload.os_type
        asset.os = payload.os_type
    if payload.owner is not None:
        asset.owner = payload.owner
    if payload.environment is not None:
        asset.environment = payload.environment
    if payload.criticality is not None:
        asset.criticality = payload.criticality
        asset.risk_score = {
            "critical": 90.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 25.0,
        }.get(payload.criticality.lower(), asset.risk_score)
    if payload.risk_level is not None:
        asset.risk_level = payload.risk_level
    if payload.classification is not None:
        asset.classification = payload.classification
        asset.exposure = payload.classification.lower()
    if payload.asset_type is not None:
        asset.asset_type = payload.asset_type
    if payload.is_active is not None:
        asset.is_active = payload.is_active

    db.commit()
    db.refresh(asset)
    return _format_asset_response(asset, db)


@router.get("/{asset_id}/misconfigurations", response_model=list[MisconfigurationBrief])
@router.get("/v1/{asset_id}/misconfigurations", response_model=list[MisconfigurationBrief])
def get_asset_misconfigurations(asset_id: str, db: Session = Depends(get_db)):
    import uuid
    try:
        uid = uuid.UUID(asset_id)
        asset = db.get(Asset, uid)
    except ValueError:
        asset = db.query(Asset).filter(Asset.hostname == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    m_list = (
        db.query(Misconfiguration)
        .join(MisconfigAsset, Misconfiguration.asset_id == MisconfigAsset.id)
        .filter(
            (MisconfigAsset.ip == asset.ip_address) |
            (MisconfigAsset.hostname == asset.hostname) |
            (MisconfigAsset.hostname == asset.asset_name)
        )
        .order_by(Misconfiguration.discovered_at.desc())
        .all()
    )

    return [
        {
            "id": m.id,
            "issue": m.issue,
            "severity": m.severity,
            "cve": m.cve,
            "detected_by": m.detected_by,
            "remediation": m.remediation,
            "status": m.status,
            "discovered_at": m.discovered_at,
        }
        for m in m_list
    ]


@router.get("/{asset_id}/details")
@router.get("/v1/{asset_id}/details")
def get_asset_full_details(asset_id: str, db: Session = Depends(get_db)):
    """Retrieve complete asset details including Agent Device state, Misconfigurations, Shadow IT, and Unauthorized Software."""
    import uuid
    from app.models.agent import AgentDevice
    try:
        uid = uuid.UUID(asset_id)
        asset = db.get(Asset, uid)
    except ValueError:
        asset = db.query(Asset).filter((Asset.hostname == asset_id) | (Asset.ip_address == asset_id)).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    formatted_asset = _format_asset_response(asset, db)

    agent_device = db.query(AgentDevice).filter(
        (AgentDevice.hostname == asset.hostname) | (AgentDevice.device_id == asset.hostname)
    ).first()

    device_info = None
    if agent_device:
        device_info = {
            "device_id": agent_device.device_id,
            "status": agent_device.status,
            "ip_address": agent_device.ip_address,
            "os_info": agent_device.os_info,
            "first_seen": agent_device.first_seen.isoformat() if agent_device.first_seen else None,
            "last_seen": agent_device.last_seen.isoformat() if agent_device.last_seen else None,
        }

    asset_findings = (
        db.query(Finding)
        .filter(Finding.asset_id == asset.id)
        .order_by(Finding.discovered_at.desc() if hasattr(Finding, "discovered_at") else Finding.last_seen.desc())
        .all()
    )
    if not asset_findings and asset.hostname:
        asset_findings = (
            db.query(Finding)
            .filter(Finding.title.contains(asset.hostname))
            .order_by(Finding.discovered_at.desc() if hasattr(Finding, "discovered_at") else Finding.last_seen.desc())
            .all()
        )

    misconfigurations = []
    shadow_it = []
    unauthorized_software = []
    other_findings = []

    for f in asset_findings:
        item = {
            "id": str(f.id),
            "title": f.title,
            "category": f.category,
            "source": f.source,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "status": f.status,
            "created_at": f.discovered_at.isoformat() if getattr(f, "discovered_at", None) else (f.last_seen.isoformat() if getattr(f, "last_seen", None) else None),
            "metadata": f.finding_metadata or {},
        }
        cat_lower = (f.category or "").lower()
        title_lower = (f.title or "").lower()

        if "misconfig" in cat_lower or (f.source == "endpoint-agent" and ("smb" in title_lower or "rdp" in title_lower or "defender" in title_lower or "uac" in title_lower or "path" in title_lower)):
            misconfigurations.append(item)
        elif "shadow" in cat_lower or "remoteaccess" in title_lower or "cloud" in title_lower or "usb" in title_lower or "anydesk" in title_lower:
            shadow_it.append(item)
        elif "software" in cat_lower or "drift" in title_lower or "unauthorized" in title_lower:
            unauthorized_software.append(item)
    from app.models.software import Software, SoftwareAsset
    installed_software_records = (
        db.query(Software, SoftwareAsset)
        .join(SoftwareAsset, Software.id == SoftwareAsset.software_id)
        .filter(
            (SoftwareAsset.asset_id == asset.id) |
            (SoftwareAsset.hostname == asset.hostname) |
            (SoftwareAsset.ip_address == asset.ip_address)
        )
        .all()
    )
    installed_software = [
        {
            "id": sw.id,
            "name": sw.name,
            "vendor": sw.vendor,
            "version": sw.version,
            "category": sw.category,
            "status": sw.status,
            "risk_score": sw.risk_score,
            "source": sa.source,
            "installed_path": sa.installed_path,
        }
        for sw, sa in installed_software_records
    ]

    return jsonable_encoder({
        "asset": formatted_asset,
        "agent_device": device_info,
        "misconfigurations": misconfigurations,
        "shadow_it": shadow_it,
        "unauthorized_software": unauthorized_software,
        "installed_software": installed_software,
        "other_findings": other_findings,
        "total_findings_count": len(misconfigurations) + len(shadow_it) + len(unauthorized_software) + len(other_findings),
    })


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
@router.delete("/v1/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst", "SecurityEngineer")
    import uuid
    try:
        uid = uuid.UUID(asset_id)
        asset = db.get(Asset, uid)
    except ValueError:
        asset = db.query(Asset).filter(Asset.hostname == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.query(Finding).filter(Finding.asset_id == asset.id).update({Finding.asset_id: None}, synchronize_session=False)
    db.delete(asset)
    db.commit()
    return None
