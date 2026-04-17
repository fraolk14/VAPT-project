from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.schedule import ScheduledScan
from app.models.user import User
from app.schemas.schedule import ScheduledScanCreate, ScheduledScanResponse
from app.services.scheduler import schedule_job
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/schedules", tags=["Schedules"])


@router.get("/", response_model=list[ScheduledScanResponse])
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(ScheduledScan).order_by(ScheduledScan.created_at.desc()).all()


@router.post("/", response_model=ScheduledScanResponse)
def create_schedule(
    payload: ScheduledScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    next_run = datetime.now(timezone.utc) + timedelta(minutes=payload.cadence_minutes)
    job = ScheduledScan(
        job_name=payload.job_name,
        scan_type=payload.scan_type,
        tool=payload.tool,
        target=payload.target,
        profile=payload.profile,
        cadence_minutes=str(payload.cadence_minutes),
        options=payload.options,
        enabled=True,
        next_run_at=next_run,
    )
    return schedule_job(db, job)


@router.post("/{schedule_id}/toggle", response_model=ScheduledScanResponse)
def toggle_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin", "analyst")
    job = db.get(ScheduledScan, schedule_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    job.enabled = not job.enabled
    db.commit()
    db.refresh(job)
    return job
