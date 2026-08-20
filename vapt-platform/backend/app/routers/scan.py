from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import AuditLog, Finding
from app.models.scan import Scan
from app.models.user import User
from app.schemas.finding import FindingOut
from app.schemas.scan import NetworkScanRequest, ScanCreate, ScanDebugResponse, ScanResponse, WebScanRequest
from app.services.integrations import ZAPClient
from app.services.mobile_analysis import persist_mobile_upload
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

    content = await file.read()
    upload_metadata = persist_mobile_upload(filename, content)
    scan = Scan(
        scan_name=label or f"Mobile Assessment {filename}",
        scan_type="mobile",
        tool="mobsf",
        target=filename,
        profile="static-analysis",
        schedule=None,
        engine_metadata={"file_name": filename, "content_type": file.content_type, **upload_metadata},
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
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        return reprocess_scan_results(db, scan)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{scan_id}/rescan", response_model=ScanResponse)
def rescan_record(
    scan_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_scan = Scan(
        scan_name=f"{scan.scan_name} (Rescan)" if not (scan.scan_name or "").endswith("(Rescan)") else scan.scan_name,
        scan_type=scan.scan_type,
        tool=scan.tool,
        target=scan.target,
        profile=scan.profile,
        schedule=scan.schedule,
        engine_metadata={},
        status="waiting",
        progress="0",
        error_message=f"{scan.scan_type.capitalize()} assessment queued. Re-scanning target in the background.",
        triggered_by=current_user.id,
    )
    new_scan = create_scan(db, new_scan)
    if new_scan.tool in {"openvas", "nmap"}:
        background_tasks.add_task(enqueue_openvas_scan, str(new_scan.id))
    elif new_scan.tool == "zap":
        background_tasks.add_task(enqueue_zap_scan, str(new_scan.id))
    elif new_scan.tool == "mobsf":
        background_tasks.add_task(enqueue_mobsf_scan, str(new_scan.id))
    return new_scan


@router.delete("/{scan_id}")
def delete_scan_record(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Disassociate or delete findings for this scan
    db.query(Finding).filter(Finding.scan_id == scan.id).delete(synchronize_session=False)
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}


# -------------------------------------------------------------------------
# ScanJob Engine Endpoints (Network, Web, Mobile)
# -------------------------------------------------------------------------
from app.models.scan import ScanJobModel
from app.schemas.scan import ScanJobCreateSchema, ScanJobResponseSchema
from app.services.misconfig_scanner import run_scan_job_engine


@router.get("/jobs", response_model=list[ScanJobResponseSchema])
@router.get("/v1/jobs", response_model=list[ScanJobResponseSchema])
def list_scan_jobs(db: Session = Depends(get_db)):
    return db.query(ScanJobModel).order_by(ScanJobModel.created_at.desc()).all()


@router.post("/jobs", response_model=ScanJobResponseSchema)
@router.post("/v1/jobs", response_model=ScanJobResponseSchema)
def create_scan_job(
    payload: ScanJobCreateSchema,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    job = ScanJobModel(
        name=payload.name,
        engine=payload.engine,
        target=payload.target,
        target_type=payload.target_type,
        status="PENDING",
        progress=0,
        scheduled_at=payload.scheduled_at,
        schedule_interval=payload.schedule_interval,
        user_id=None,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(run_scan_job_engine, job.id)
    return job


@router.get("/jobs/{job_id}", response_model=ScanJobResponseSchema)
@router.get("/v1/jobs/{job_id}", response_model=ScanJobResponseSchema)
def get_scan_job(job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJobModel, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/jobs/{job_id}/cancel", response_model=ScanJobResponseSchema)
@router.post("/v1/jobs/{job_id}/cancel", response_model=ScanJobResponseSchema)
def cancel_scan_job(job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJobModel, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    job.status = "CANCELLED"
    db.commit()
    db.refresh(job)
    return job


@router.delete("/jobs/{job_id}")
@router.delete("/v1/jobs/{job_id}")
def delete_scan_job(job_id: int, db: Session = Depends(get_db)):
    job = db.get(ScanJobModel, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    db.delete(job)
    db.commit()
    return {"message": "Scan job deleted successfully"}


@router.post("/jobs/{job_id}/rescan", response_model=ScanJobResponseSchema)
@router.post("/v1/jobs/{job_id}/rescan", response_model=ScanJobResponseSchema)
def rescan_scan_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    job = db.get(ScanJobModel, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    new_job = ScanJobModel(
        name=f"{job.name} (Rescan)" if not job.name.endswith("(Rescan)") else job.name,
        engine=job.engine,
        target=job.target,
        target_type=job.target_type,
        status="PENDING",
        progress=0,
        schedule_interval=job.schedule_interval,
        asset_id=job.asset_id,
        user_id=job.user_id,
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    background_tasks.add_task(run_scan_job_engine, new_job.id)
    return new_job


