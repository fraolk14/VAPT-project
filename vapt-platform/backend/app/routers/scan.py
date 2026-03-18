from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import Scan
from app.models.user import User
from app.schemas.scan import NetworkScanRequest, ScanCreate, ScanResponse
from app.services.orchestrator import create_scan, enqueue_openvas_scan, refresh_openvas_scan, run_mock_scan
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse)
def create_scan_record(
    scan: ScanCreate,
    background_tasks: BackgroundTasks,
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
    if scan.tool == "openvas":
        db_scan.status = "waiting"
        db_scan.progress = "0"
        db_scan.error_message = "Network engine queued. Discovery will begin automatically in the background."
        db.commit()
        db.refresh(db_scan)
        background_tasks.add_task(enqueue_openvas_scan, str(db_scan.id))
        return db_scan
    return run_mock_scan(db, db_scan)


@router.post("/network", response_model=ScanResponse)
def create_network_scan(
    payload: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan = Scan(
        scan_name=payload.label or f"Network Assessment {payload.target}",
        scan_type="network",
        tool="openvas",
        target=payload.target,
        profile="Full and fast",
        schedule=None,
        engine_metadata={},
        status="waiting",
        progress="0",
        error_message="Network engine queued. Discovery will begin automatically in the background.",
        triggered_by=None,
    )
    scan = create_scan(db, scan)
    background_tasks.add_task(enqueue_openvas_scan, str(scan.id))
    return scan


@router.get("/", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    refreshed = []
    for scan in scans:
        if scan.tool == "openvas" and scan.status in {"waiting", "queued", "running"}:
            refreshed.append(refresh_openvas_scan(db, scan))
        else:
            refreshed.append(scan)
    return refreshed
