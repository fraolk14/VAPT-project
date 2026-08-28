from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.software import Software, SoftwareAsset, WhitelistSoftware
from app.services.software_discovery import process_software_governance, run_nmap_service_discovery, run_wmi_discovery

router = APIRouter(prefix="/software", tags=["Software Governance"])


class SoftwareResponse(BaseModel):
    id: int
    name: str
    vendor: str | None = None
    version: str | None = None
    category: str
    cpe: str | None = None
    status: str
    risk_score: float
    cves: list[str] = []
    ip_address: str | None = None
    source: str | None = None
    discovered_at: datetime
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class WhitelistCreate(BaseModel):
    name: str
    vendor: str | None = None
    reason: str | None = "Approved by Security Team"


class WhitelistResponse(BaseModel):
    id: int
    name: str
    vendor: str | None = None
    reason: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class DiscoverRequest(BaseModel):
    target: str  # IP address or Hostname
    asset_id: str | None = None


@router.get("", response_model=list[SoftwareResponse])
def list_software(
    status_filter: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    """Retrieve all software entries from the PostgreSQL database along with target IP and discovery source."""
    query = db.query(Software)
    if status_filter:
        query = query.filter(Software.status == status_filter.upper())
    
    items = query.order_by(Software.risk_score.desc(), Software.discovered_at.desc()).all()
    results = []
    
    for sw in items:
        link = db.query(SoftwareAsset).filter(SoftwareAsset.software_id == sw.id).order_by(SoftwareAsset.discovered_at.desc()).first()
        res = SoftwareResponse(
            id=sw.id,
            name=sw.name,
            vendor=sw.vendor,
            version=sw.version,
            category=sw.category,
            cpe=sw.cpe,
            status=sw.status,
            risk_score=sw.risk_score,
            cves=sw.cves or [],
            ip_address=link.ip_address if (link and link.ip_address) else "127.0.0.1",
            source=link.source if link else "Nmap -sV Subprocess",
            discovered_at=sw.discovered_at,
            updated_at=sw.updated_at,
        )
        results.append(res)
        
    return results


@router.get("/whitelist", response_model=list[WhitelistResponse])
def list_whitelist(db: Session = Depends(get_db)):
    """Retrieve all approved whitelisted software entries from PostgreSQL."""
    return db.query(WhitelistSoftware).order_by(WhitelistSoftware.created_at.desc()).all()


@router.post("/whitelist", response_model=WhitelistResponse, status_code=status.HTTP_201_CREATED)
def add_to_whitelist(payload: WhitelistCreate, db: Session = Depends(get_db)):
    """Add a software to the approved whitelist in PostgreSQL and update existing software status."""
    existing = db.query(WhitelistSoftware).filter(WhitelistSoftware.name.ilike(payload.name.strip())).first()
    if existing:
        raise HTTPException(status_code=409, detail="Software is already present in the approved whitelist.")
    
    entry = WhitelistSoftware(
        name=payload.name.strip(),
        vendor=payload.vendor,
        reason=payload.reason,
    )
    db.add(entry)
    
    # Update status of any existing matching software in PostgreSQL database
    matching_sw = db.query(Software).filter(Software.name.ilike(payload.name.strip())).all()
    for sw in matching_sw:
        sw.status = "APPROVED"
        sw.updated_at = datetime.now(timezone.utc)
    
    db.commit()
    db.refresh(entry)
    return entry


@router.delete("/whitelist/{whitelist_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_from_whitelist(whitelist_id: int, db: Session = Depends(get_db)):
    """Remove a software from the approved whitelist."""
    entry = db.get(WhitelistSoftware, whitelist_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Whitelist entry not found.")
    
    sw_name = entry.name
    db.delete(entry)
    
    # Re-evaluate matching software status back to UNAUTHORIZED / VULNERABLE
    matching_sw = db.query(Software).filter(Software.name.ilike(sw_name)).all()
    for sw in matching_sw:
        if sw.risk_score >= 7.0 or len(sw.cves or []) > 0:
            sw.status = "VULNERABLE"
        else:
            sw.status = "UNAUTHORIZED"
        sw.updated_at = datetime.now(timezone.utc)
        
    db.commit()
    return None


@router.post("/discover", response_model=list[SoftwareResponse])
def discover_software_on_target(payload: DiscoverRequest, db: Session = Depends(get_db)):
    """Run real discovery on target host via WMI/Nmap/Lynis and classify results in PostgreSQL database."""
    target_str = payload.target.strip()
    asset = None
    if payload.asset_id:
        asset = db.get(Asset, payload.asset_id)
    if not asset:
        asset = db.query(Asset).filter((Asset.ip_address == target_str) | (Asset.hostname == target_str)).first()

    asset_id_val = str(asset.id) if asset else None

    # Run real discovery processes
    wmi_results = run_wmi_discovery(target_str)
    nmap_results = run_nmap_service_discovery(target_str)
    
    processed: list[Software] = []
    
    for item in wmi_results:
        sw = process_software_governance(
            db,
            software_name=item["name"],
            vendor=item.get("vendor"),
            version=item.get("version"),
            category=item.get("category", "OS"),
            asset_id=asset_id_val,
            installed_path=item.get("installed_path"),
            ip_address=target_str,
            hostname=asset.hostname if asset else target_str,
            endpoint_name=asset.asset_name if asset else target_str,
            source="WMI Subprocess",
        )
        processed.append(sw)

    for item in nmap_results:
        sw = process_software_governance(
            db,
            software_name=item["name"],
            vendor=item.get("vendor"),
            version=item.get("version"),
            category=item.get("category", "Network"),
            asset_id=asset_id_val,
            installed_path=item.get("installed_path"),
            ip_address=target_str,
            hostname=asset.hostname if asset else target_str,
            endpoint_name=asset.asset_name if asset else target_str,
            source="Nmap -sV Subprocess",
        )
        processed.append(sw)
        
    return processed


@router.post("/bulk-whitelist")
def bulk_whitelist_software(db: Session = Depends(get_db)):
    """Bulk approve all discovered software items across all managed endpoints and update whitelist baseline policy."""
    from app.models.finding import Finding
    all_sw = db.query(Software).all()
    count = 0
    for sw in all_sw:
        sw.status = "APPROVED"
        sw.updated_at = datetime.now(timezone.utc)
        
        existing = db.query(WhitelistSoftware).filter(WhitelistSoftware.name.ilike(sw.name.strip())).first()
        if not existing:
            wl_entry = WhitelistSoftware(
                name=sw.name.strip(),
                vendor=sw.vendor,
                reason="Bulk Whitelisted across all endpoints",
            )
            db.add(wl_entry)
        count += 1

    db.query(Finding).filter(Finding.category == "Software Drift").update({Finding.status: "RESOLVED"}, synchronize_session=False)
    db.commit()
    return {"message": f"Successfully whitelisted {count} software applications across all managed endpoints.", "whitelisted_count": count}


@router.post("/discover-subnet")
def discover_subnet_software(payload: dict[str, Any], db: Session = Depends(get_db)):
    """Run real software discovery across a specified subnet range across all endpoints."""
    subnet = payload.get("subnet", "").strip() or "192.168.10.0/24"
    assets = db.query(Asset).all()
    results = []
    
    for a in assets:
        target = a.ip_address or a.hostname
        if not target:
            continue
        try:
            wmi_res = run_wmi_discovery(target)
            nmap_res = run_nmap_service_discovery(target)
            
            for item in wmi_res + nmap_res:
                sw = process_software_governance(
                    db,
                    software_name=item["name"],
                    vendor=item.get("vendor"),
                    version=item.get("version"),
                    category=item.get("category", "Application"),
                    asset_id=str(a.id),
                    installed_path=item.get("installed_path"),
                    ip_address=a.ip_address or "127.0.0.1",
                    hostname=a.hostname,
                    endpoint_name=a.asset_name or a.hostname,
                    source="Subnet WMI/Nmap Discovery",
                )
                results.append(sw)
        except Exception as e:
            print(f"[SubnetDiscovery] Error discovering {target}: {e}")

    return {"message": f"Discovered software across subnet {subnet}.", "total_items_found": len(results)}


@router.post("/rediscover-managed")
def rediscover_managed_devices_software(
    target_asset_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    """
    Run active software and service re-discovery across all managed devices in asset inventory.
    Optionally targets a specific managed device by asset_id.
    """
    query = db.query(Asset)
    if target_asset_id:
        query = query.filter(Asset.id == target_asset_id)
    else:
        # Prefer active assets
        active_assets = query.filter(Asset.is_active.is_(True)).all()
        managed_assets = active_assets if active_assets else query.all()

    if target_asset_id:
        managed_assets = query.all()

    discovered_software_items = []
    scanned_devices = []

    for asset in managed_assets:
        target_ip = (asset.ip_address or "").strip()
        target_host = (asset.hostname or "").strip()
        target = target_ip or target_host
        if not target or target in {"127.0.0.1", "localhost", "0.0.0.0"}:
            continue

        device_label = asset.asset_name or target_host or target_ip
        scanned_devices.append(device_label)
        try:
            # 1. Windows WMI discovery if OS is Windows or unspecified
            wmi_results = []
            if not asset.os or "win" in str(asset.os).lower() or "windows" in str(asset.os_type).lower():
                wmi_results = run_wmi_discovery(target)
            
            # 2. Network service & version discovery (Nmap -sV & socket banner probing)
            nmap_results = run_nmap_service_discovery(target)

            combined = wmi_results + nmap_results
            for item in combined:
                sw = process_software_governance(
                    db,
                    software_name=item["name"],
                    vendor=item.get("vendor"),
                    version=item.get("version"),
                    category=item.get("category", "Application"),
                    asset_id=str(asset.id),
                    installed_path=item.get("installed_path"),
                    ip_address=target_ip or "127.0.0.1",
                    hostname=target_host or target_ip,
                    endpoint_name=asset.asset_name or target_host or target_ip,
                    source=item.get("source", "Managed Device Discovery"),
                )
                discovered_software_items.append(sw)
        except Exception as exc:
            print(f"[ManagedDeviceDiscovery] Note for device {device_label} ({target}): {exc}")

    return {
        "message": f"Successfully re-discovered {len(discovered_software_items)} software items across {len(scanned_devices)} managed devices.",
        "scanned_devices_count": len(scanned_devices),
        "total_items_found": len(discovered_software_items),
        "devices": scanned_devices[:10],
    }

