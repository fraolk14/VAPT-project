from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse
from app.services.orchestrator import create_scan, run_scan
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse)
def create_scan_record(
    scan: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    if scan.tool not in {"openvas", "zap", "mobsf"}:
        raise HTTPException(status_code=400, detail="Unsupported scan engine")

    db_scan = Scan(
        scan_name=scan.scan_name,
        scan_type=scan.scan_type,
        tool=scan.tool,
        target=scan.target,
        profile=scan.profile,
        schedule=scan.schedule,
        engine_metadata=scan.options,
        status="queued",
        triggered_by=current_user.id,
    )
    db_scan = create_scan(db, db_scan)
    return run_scan(db, db_scan)


@router.get("/", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()
