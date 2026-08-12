from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.asset import Asset
from app.models.finding import AuditLog, Finding
from app.models.platform import EndpointSoftwareInventory
from app.models.user import User
from app.schemas.posture import (
    EndpointSoftwareIngest,
    EndpointSoftwareInventoryResponse,
    MisconfigurationSummary,
    ShadowITSummary,
    UnauthorizedSoftwareSummary,
)
from app.services.posture import (
    build_misconfiguration_summary,
    build_shadow_it_summary,
    build_software_summary,
    classify_installed_apps,
)
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/posture", tags=["Posture"])


@router.get("/shadow-it", response_model=ShadowITSummary)
def shadow_it_summary(db: Session = Depends(get_db)):
    return ShadowITSummary(**build_shadow_it_summary(db.query(Asset).all(), db.query(Finding).all()))


@router.get("/misconfigurations", response_model=MisconfigurationSummary)
def misconfiguration_summary(db: Session = Depends(get_db)):
    return MisconfigurationSummary(**build_misconfiguration_summary(db.query(Finding).all()))


@router.get("/unauthorized-software", response_model=UnauthorizedSoftwareSummary)
def unauthorized_software_summary(db: Session = Depends(get_db)):
    return UnauthorizedSoftwareSummary(
        **build_software_summary(
            db.query(Asset).all(),
            db.query(EndpointSoftwareInventory).all(),
            db.query(Finding).all(),
            db=db,
        )
    )


@router.get("/unauthorized-software/inventory", response_model=list[EndpointSoftwareInventoryResponse])
def list_software_inventory(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(EndpointSoftwareInventory).order_by(EndpointSoftwareInventory.updated_at.desc()).limit(100).all()


@router.post("/unauthorized-software/ingest", response_model=EndpointSoftwareInventoryResponse)
def ingest_software_inventory(
    payload: EndpointSoftwareIngest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    detected_apps = classify_installed_apps(payload.installed_apps, payload.approved_baseline)
    inventory = EndpointSoftwareInventory(
        endpoint_name=payload.endpoint_name,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        os_name=payload.os_name,
        source=payload.source,
        reported_by=current_user.username,
        installed_apps=payload.installed_apps,
        approved_baseline=payload.approved_baseline,
        detected_apps=detected_apps,
        status="review_required" if detected_apps else "approved",
    )
    db.add(inventory)
    db.flush()
    db.add(
        AuditLog(
            actor=current_user.username,
            action="software_inventory.ingest",
            resource_type="endpoint_software_inventory",
            resource_id=str(inventory.id),
            details={
                "endpoint_name": inventory.endpoint_name,
                "installed_count": len(payload.installed_apps),
                "detected_count": len(detected_apps),
            },
        )
    )
    db.commit()
    db.refresh(inventory)
    return inventory
