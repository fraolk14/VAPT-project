import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.finding import AuditLog, Finding
from app.models.scan import Scan
from app.services.integrations import MobSFClient, OpenVASClient, ZAPClient

_active_workers: set[str] = set()
_worker_lock = threading.Lock()


def _mock_results(scan: Scan) -> list[dict[str, Any]]:
    if scan.tool == "zap":
        return ZAPClient().normalize_results(
            [
                {
                    "alert": "Reflected XSS",
                    "port": 443,
                    "protocol": "https",
                    "risk_score": 8.2,
                    "url": scan.target,
                    "solution": "Apply output encoding and CSP.",
                }
            ]
        )
    return MobSFClient().normalize_results(
        [
            {
                "title": "Hardcoded secret",
                "cvss": 8.8,
                "description": "API token embedded in binary resources.",
                "recommendation": "Move the secret to a remote secret manager.",
                "file": scan.target,
            }
        ]
    )


def create_scan(db: Session, scan: Scan) -> Scan:
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def _set_scan_state(
    db: Session,
    scan: Scan,
    *,
    status: str | None = None,
    progress: str | None = None,
    error_message: str | None = None,
) -> None:
    if status is not None:
        scan.status = status
    if progress is not None:
        scan.progress = progress
    scan.error_message = error_message
    db.commit()
    db.refresh(scan)


def _store_findings(db: Session, scan: Scan, normalized_findings: list[dict[str, Any]]) -> None:
    if scan.result_summary.get("ingested"):
        return

    for item in normalized_findings:
        db.add(
            Finding(
                scan_id=scan.id,
                title=item["title"],
                category=item["category"],
                source=item["source"],
                status="open",
                port=item["port"],
                protocol=item["protocol"],
                service=item.get("service"),
                state=item["state"],
                cve_id=item.get("cve_id"),
                cvss_score=item.get("cvss_score"),
                severity=item.get("severity"),
                confidence=0.86,
                evidence=item.get("evidence"),
                remediation=item.get("remediation"),
                compliance_map=item.get("compliance_map", []),
                finding_metadata=item.get("metadata", {}),
            )
        )

    scan.result_summary = {
        **scan.result_summary,
        "finding_count": len(normalized_findings),
        "sources": [scan.tool],
        "target": scan.target,
        "ingested": True,
    }


def run_mock_scan(db: Session, scan: Scan) -> Scan:
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = "35"
    db.commit()

    normalized_findings = _mock_results(scan)
    _store_findings(db, scan, normalized_findings)

    scan.status = "completed"
    scan.progress = "100"
    scan.finished_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            actor=scan.triggered_by or "system",
            action="scan.execute",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"tool": scan.tool, "target": scan.target},
        )
    )
    db.commit()
    db.refresh(scan)
    return scan


def launch_openvas_scan(db: Session, scan: Scan) -> Scan:
    client = OpenVASClient()
    metadata = client.launch_scan(scan.target, scan.profile)

    scan.status = "queued"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = "0"
    scan.error_message = None
    scan.engine_metadata = {**scan.engine_metadata, **metadata}
    db.add(
        AuditLog(
            actor=scan.triggered_by or "system",
            action="scan.launch",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"tool": scan.tool, "target": scan.target, "remote_task_id": metadata["remote_task_id"]},
        )
    )
    db.commit()
    db.refresh(scan)
    return refresh_openvas_scan(db, scan)


def refresh_openvas_scan(db: Session, scan: Scan) -> Scan:
    remote_task_id = (scan.engine_metadata or {}).get("remote_task_id")
    if not remote_task_id:
        return scan

    client = OpenVASClient()
    status = client.get_task_status(remote_task_id)
    report_id = status.get("remote_report_id") or (scan.engine_metadata or {}).get("remote_report_id")

    scan.status = status["status"]
    scan.progress = str(status.get("progress", "0"))
    scan.error_message = None
    scan.engine_metadata = {
        **scan.engine_metadata,
        "status_text": status.get("status_text"),
        "remote_report_id": report_id,
    }

    if scan.status == "completed" and report_id and not scan.result_summary.get("ingested"):
        normalized_findings = client.get_report_results(report_id)
        _store_findings(db, scan, normalized_findings)
        scan.finished_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)
    return scan


def _background_openvas_worker(scan_id: str) -> None:
    try:
        for _ in range(240):
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if not scan:
                    return

                if scan.status in {"completed", "failed"}:
                    return

                if not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(scan)

                remote_task_id = (scan.engine_metadata or {}).get("remote_task_id")

                if not remote_task_id:
                    try:
                        launch_openvas_scan(db, scan)
                    except RuntimeError as exc:
                        _set_scan_state(
                            db,
                            scan,
                            status="waiting",
                            progress="0",
                            error_message="Network engine is synchronizing intelligence feeds. The scan will start automatically when ready.",
                        )
                    else:
                        scan = db.get(Scan, scan_id)
                        if scan and scan.status == "completed":
                            return
                else:
                    refresh_openvas_scan(db, scan)
                    scan = db.get(Scan, scan_id)
                    if scan and scan.status == "completed":
                        return
            finally:
                db.close()

            time.sleep(30)
    finally:
        with _worker_lock:
            _active_workers.discard(scan_id)


def enqueue_openvas_scan(scan_id: str) -> None:
    with _worker_lock:
        if scan_id in _active_workers:
            return
        _active_workers.add(scan_id)

    worker = threading.Thread(
        target=_background_openvas_worker,
        args=(scan_id,),
        daemon=True,
        name=f"openvas-scan-{scan_id}",
    )
    worker.start()
