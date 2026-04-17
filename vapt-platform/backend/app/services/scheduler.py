from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.scan import Scan
from app.models.schedule import ScheduledScan
from app.services.orchestrator import create_scan, enqueue_mobsf_scan, enqueue_openvas_scan, enqueue_zap_scan

_scheduler_lock = threading.Lock()
_scheduler_started = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def initialize_next_run(job: ScheduledScan) -> None:
    if not job.next_run_at:
        job.next_run_at = _now() + timedelta(minutes=int(job.cadence_minutes))


def schedule_job(db: Session, job: ScheduledScan) -> ScheduledScan:
    initialize_next_run(job)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def run_due_schedules() -> None:
    db = SessionLocal()
    try:
        jobs = (
            db.query(ScheduledScan)
            .filter(ScheduledScan.enabled.is_(True))
            .all()
        )
        now = _now()
        for job in jobs:
            initialize_next_run(job)
            if not job.next_run_at or job.next_run_at > now:
                continue

            scan = Scan(
                scan_name=f"{job.job_name} ({now.strftime('%Y-%m-%d %H:%M')})",
                scan_type=job.scan_type,
                tool=job.tool,
                target=job.target,
                profile=job.profile,
                schedule=f"every {job.cadence_minutes} minutes",
                engine_metadata={**(job.options or {}), "scheduled_job_id": str(job.id)},
                status="waiting",
                progress="0",
                error_message="Scheduled assessment queued automatically.",
                triggered_by=None,
            )
            scan = create_scan(db, scan)
            if job.tool == "openvas":
                enqueue_openvas_scan(str(scan.id))
            elif job.tool == "zap":
                enqueue_zap_scan(str(scan.id))
            elif job.tool == "mobsf":
                enqueue_mobsf_scan(str(scan.id))

            job.last_run_at = now
            job.next_run_at = now + timedelta(minutes=int(job.cadence_minutes))
            db.commit()
    finally:
        db.close()


def _scheduler_loop() -> None:
    while True:
        try:
            run_due_schedules()
        except Exception:
            pass
        time.sleep(30)


def start_scheduler() -> None:
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    worker = threading.Thread(target=_scheduler_loop, daemon=True, name="scheduled-scan-runner")
    worker.start()
