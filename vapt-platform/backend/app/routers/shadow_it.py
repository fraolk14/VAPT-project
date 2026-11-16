import ipaddress
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import AuditLog
from app.services.security import get_current_user, require_analyst
from app.services.shadow_it import REVIEW_PREFIX, build_shadow_posture

router = APIRouter(tags=["Shadow IT Discovery"])


class DeviceReview(BaseModel):
    decision: Literal["sanctioned", "unsanctioned", "unreviewed"]
    owner: str | None = Field(default=None, max_length=200)
    business_unit: str | None = Field(default=None, max_length=120)


class RegisterHost(BaseModel):
    address: str = Field(min_length=1, max_length=255)
    owner: str | None = Field(default=None, max_length=200)


@router.get("/shadow-it/posture")
@router.get("/v1/shadow-it/posture")
def shadow_it_posture(db: Session = Depends(get_db)):
    """Unreviewed discovered devices, hosts missing from inventory and unsanctioned endpoint apps."""
    return build_shadow_posture(db)


@router.post("/shadow-it/devices/{asset_id}/review", dependencies=[Depends(require_analyst)])
def review_device(asset_id: str, payload: DeviceReview, db: Session = Depends(get_db), user=Depends(get_current_user)):
    try:
        asset = db.get(Asset, uuid.UUID(asset_id))
    except ValueError:
        asset = None
    if not asset:
        raise HTTPException(status_code=404, detail="Device not found")
    before = {"tags": list(asset.tags or []), "owner": asset.owner, "business_unit": asset.business_unit}
    tags = [t for t in (asset.tags or []) if not str(t).startswith(REVIEW_PREFIX)]
    if payload.decision != "unreviewed":
        tags.append(f"{REVIEW_PREFIX}{payload.decision}")
    asset.tags = sorted(set(tags))
    if payload.owner is not None:
        asset.owner = payload.owner.strip() or None
    if payload.business_unit is not None:
        asset.business_unit = payload.business_unit.strip() or None
    db.add(AuditLog(
        actor=user.username,
        action=f"shadow_it.review.{payload.decision}",
        resource_type="asset",
        resource_id=str(asset.id),
        details={"address": asset.ip_address or asset.hostname, "before": before,
                 "after": {"tags": asset.tags, "owner": asset.owner, "business_unit": asset.business_unit}},
    ))
    db.commit()
    return {"id": str(asset.id), "state": payload.decision, "owner": asset.owner, "business_unit": asset.business_unit}


@router.post("/shadow-it/untracked/register", dependencies=[Depends(require_analyst)])
def register_untracked_host(payload: RegisterHost, db: Session = Depends(get_db), user=Depends(get_current_user)):
    address = payload.address.strip()
    try:
        ipaddress.ip_address(address)
        ip, hostname = address, address
    except ValueError:
        ip, hostname = "", address
    existing = db.query(Asset).filter((Asset.ip_address == address) | (Asset.hostname == address)).first()
    if existing:
        raise HTTPException(status_code=409, detail="That host is already in the inventory.")
    asset = Asset(
        asset_name=address,
        hostname=hostname,
        ip_address=ip,
        owner=(payload.owner or "").strip() or None,
        environment="Production",
        criticality="Medium",
        classification="Internal",
        exposure="internal",
        asset_type="host",
        business_unit="Discovered",
        tags=["scan-discovered", "added-from-shadow-it"],
        is_active=True,
    )
    db.add(asset)
    db.flush()
    db.add(AuditLog(actor=user.username, action="shadow_it.register", resource_type="asset", resource_id=str(asset.id),
                    details={"address": address, "owner": asset.owner}))
    db.commit()
    return {"id": str(asset.id), "address": address}
