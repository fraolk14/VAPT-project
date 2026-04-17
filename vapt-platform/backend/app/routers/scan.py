from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import AuditLog, Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingOut
from app.schemas.scan import NetworkScanRequest, ScanCreate, ScanDebugResponse, ScanResponse, WebScanRequest
from app.services.integrations import ZAPClient
from app.services.orchestrator import (
    cancel_scan,
    create_scan,
    enqueue_mobsf_scan,
    enqueue_openvas_scan,
    enqueue_zap_scan,
    pause_scan,
    reprocess_scan_results,
    resume_scan,
    run_mock_scan,
)
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
    normalized_target = scan.target
    if scan.tool == "zap":
        try:
            normalized_target = ZAPClient().normalize_target(scan.target)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    db_scan = Scan(
        scan_name=scan.scan_name,
        scan_type=scan.scan_type,
        tool=scan.tool,
        target=normalized_target,
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
        db_scan.error_message = "Deep network assessment queued. Extended port discovery, service validation, and vulnerability correlation will begin automatically in the background."
        db.commit()
        db.refresh(db_scan)
        background_tasks.add_task(enqueue_openvas_scan, str(db_scan.id))
        return db_scan
    if scan.tool == "zap":
        db_scan.scan_type = "web"
        db_scan.profile = scan.profile or "spider-active"
        db_scan.status = "waiting"
        db_scan.progress = "0"
        db_scan.error_message = "Web engine queued. Spidering and active scanning will begin automatically in the background."
        db.commit()
        db.refresh(db_scan)
        background_tasks.add_task(enqueue_zap_scan, str(db_scan.id))
        return db_scan
    db_scan.scan_type = "mobile"
    db_scan.status = "waiting"
    db_scan.progress = "0"
    db_scan.error_message = "Mobile engine queued. Static analysis will begin automatically in the background."
    db.commit()
    db.refresh(db_scan)
    background_tasks.add_task(enqueue_mobsf_scan, str(db_scan.id))
    return db_scan


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
        error_message="Deep network assessment queued. Extended port discovery, service validation, and vulnerability correlation will begin automatically in the background.",
        triggered_by=None,
    )
    scan = create_scan(db, scan)
    background_tasks.add_task(enqueue_openvas_scan, str(scan.id))
    return scan


@router.post("/web", response_model=ScanResponse)
def create_web_scan(
    payload: WebScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    try:
        normalized_target = ZAPClient().normalize_target(payload.target)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        scan_name=payload.label or f"Web Assessment {normalized_target}",
        scan_type="web",
        tool="zap",
        target=normalized_target,
        profile="spider-active",
        schedule=None,
        engine_metadata={},
        status="waiting",
        progress="0",
        error_message="Web engine queued. Spidering and active scanning will begin automatically in the background.",
        triggered_by=None,
    )
    scan = create_scan(db, scan)
    background_tasks.add_task(enqueue_zap_scan, str(scan.id))
    return scan


@router.post("/mobile", response_model=ScanResponse)
async def create_mobile_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    label: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    filename = file.filename or ""
    lowered = filename.lower()
    if not lowered.endswith((".apk", ".ipa", ".aab")):
        raise HTTPException(status_code=400, detail="Mobile scans require an APK, IPA, or AAB file.")

    await file.read()
    scan = Scan(
        scan_name=label or f"Mobile Assessment {filename}",
        scan_type="mobile",
        tool="mobsf",
        target=filename,
        profile="static-analysis",
        schedule=None,
        engine_metadata={"file_name": filename, "content_type": file.content_type},
        status="waiting",
        progress="0",
        error_message="Mobile engine queued. Static analysis will begin automatically in the background.",
        triggered_by=None,
    )
    scan = create_scan(db, scan)
    background_tasks.add_task(enqueue_mobsf_scan, str(scan.id))
    return scan


@router.get("/", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.created_at.desc()).all()


@router.get("/{scan_id}/debug", response_model=ScanDebugResponse)
def get_scan_debug(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(Finding.detected_at.desc())
        .all()
    )
    audit_logs = (
        db.query(AuditLog)
        .filter(AuditLog.resource_type == "scan", AuditLog.resource_id == str(scan.id))
        .order_by(AuditLog.created_at.desc())
        .limit(20)
        .all()
    )
    return ScanDebugResponse(
        id=scan.id,
        scan_name=scan.scan_name,
        tool=scan.tool,
        status=scan.status,
        target=scan.target,
        progress=scan.progress,
        error_message=scan.error_message,
        engine_metadata=scan.engine_metadata or {},
        result_summary=scan.result_summary or {},
        related_findings=[
            FindingOut.model_validate({**finding.__dict__, "scan_finished_at": scan.finished_at})
            for finding in findings
        ],
        audit_trail=[
            {
                "id": str(item.id),
                "action": item.action,
                "actor": item.actor,
                "outcome": item.outcome,
                "details": item.details,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in audit_logs
        ],
    )


@router.post("/{scan_id}/pause", response_model=ScanResponse)
def pause_scan_record(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return pause_scan(db, scan)


@router.post("/{scan_id}/resume", response_model=ScanResponse)
def resume_scan_record(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return resume_scan(db, scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan_record(scan_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cancel_scan(db, scan)


@router.post("/{scan_id}/reprocess", response_model=ScanResponse)
def reprocess_scan_record(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        return reprocess_scan_results(db, scan)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
