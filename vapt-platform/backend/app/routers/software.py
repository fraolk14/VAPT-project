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
