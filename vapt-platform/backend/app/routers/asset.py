from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User
from app.schemas.asset import AssetCreate, AssetResponse
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.post("/", response_model=AssetResponse)
def create_asset(
    asset: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    payload = asset.model_dump()
    payload["risk_score"] = {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get((asset.criticality or "medium").lower(), 5.0)
    existing = None
    if payload.get("url"):
        existing = db.query(Asset).filter(Asset.url == payload["url"]).first()
    if not existing and payload.get("ip_address"):
        existing = db.query(Asset).filter(Asset.ip_address == payload["ip_address"]).first()
    if existing:
        for key, value in payload.items():
            if value not in {None, "", []}:
                setattr(existing, key, value)
        db.commit()
        db.refresh(existing)
        return existing
    db_asset = Asset(**payload)
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.get("/", response_model=list[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.risk_score.desc()).all()


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.query(Finding).filter(Finding.asset_id == asset.id).update({Finding.asset_id: None}, synchronize_session=False)
    db.delete(asset)
    db.commit()
    return None
