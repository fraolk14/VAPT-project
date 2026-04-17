import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.asset import Asset
from app.models.finding import AuditLog, FalsePositiveRule, Finding
from app.models.scan import Scan
from app.services.integrations import MobSFClient, OpenVASClient, ZAPClient
from app.services.network_assessment import run_network_assessment
from app.services.vulnerability_correlation import correlate_finding

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


def _append_audit_log(db: Session, scan: Scan, action: str, details: dict[str, Any] | None = None) -> None:
    db.add(
        AuditLog(
            actor=scan.triggered_by or "system",
            action=action,
            resource_type="scan",
            resource_id=str(scan.id),
            details=details or {"tool": scan.tool, "target": scan.target},
        )
    )
    db.commit()
    db.refresh(scan)


def _finding_asset_name(scan: Scan, metadata: dict[str, Any], item: dict[str, Any]) -> str:
    if metadata.get("page_title"):
        return str(metadata["page_title"])[:80]
    if metadata.get("host"):
        return str(metadata["host"])
    if metadata.get("url"):
        host = urlparse(str(metadata["url"])).hostname
        return host or str(metadata["url"])[:80]
    return scan.target


def _upsert_asset_from_finding(db: Session, scan: Scan, item: dict[str, Any], metadata: dict[str, Any]) -> Asset | None:
    host = metadata.get("host")
    url = metadata.get("url") or (scan.target if scan.tool == "zap" and "://" in scan.target else None)
    hostname = metadata.get("hostname") or (urlparse(str(url)).hostname if url else None)
    ip_address = str(host or hostname or "").strip()
    if not ip_address and not url:
        return None

    asset = None
    if url:
        asset = db.query(Asset).filter(Asset.url == str(url)).first()
    if not asset and ip_address:
        asset = db.query(Asset).filter(Asset.ip_address == ip_address).first()
    if not asset and hostname:
        asset = db.query(Asset).filter(Asset.hostname == hostname).first()

    asset_type = "web" if url or item.get("service") in {"http", "https", "apache", "nginx", "iis"} else "host"
    exposure = "internal"
    if url and hostname and not hostname.endswith((".local", ".lan")):
        exposure = "external"

    if asset:
        asset.hostname = asset.hostname or hostname
        asset.url = asset.url or url
        asset.asset_type = asset.asset_type or asset_type
        asset.tags = sorted(set([*(asset.tags or []), "scan-discovered", f"service:{item.get('service') or 'unknown'}"]))
        asset.risk_score = max(asset.risk_score or 0, float(item.get("cvss_score") or 0))
        return asset

    asset = Asset(
        asset_name=_finding_asset_name(scan, metadata, item),
        ip_address=ip_address or str(url),
        url=str(url) if url else None,
        hostname=hostname or (None if ip_address == str(host) else ip_address),
        asset_type=asset_type,
        environment="prod",
        criticality="high" if (item.get("severity") or "").lower() in {"critical", "high"} else "medium",
        owner=None,
        exposure=exposure,
        tags=["scan-discovered", f"service:{item.get('service') or 'unknown'}"],
        business_unit="Discovered",
        risk_score=float(item.get("cvss_score") or 0),
    )
    db.add(asset)
    db.flush()
    return asset


def _store_findings(db: Session, scan: Scan, normalized_findings: list[dict[str, Any]]) -> None:
    if scan.result_summary.get("ingested"):
        return

    rules = db.query(FalsePositiveRule).filter(FalsePositiveRule.enabled.is_(True)).all()
    correlated_findings = [correlate_finding(item, db=db) for item in normalized_findings]

    for item in correlated_findings:
        status = "open"
        metadata = item.get("metadata", {})
        for rule in rules:
            title_match = rule.title_pattern.lower() in item["title"].lower()
            cve_match = not rule.cve_id or rule.cve_id == item.get("cve_id")
            source_match = not rule.source or rule.source == item["source"]
            if title_match and cve_match and source_match:
                status = "false_positive"
                metadata = {
                    **metadata,
                    "triage": {
                        **metadata.get("triage", {}),
                        "suppressed_by_rule": str(rule.id),
                    },
                }
                break
        asset = _upsert_asset_from_finding(db, scan, item, metadata)
        db.add(
            Finding(
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
                title=item["title"],
                category=item["category"],
                source=item["source"],
                status=status,
                port=item["port"],
                protocol=item["protocol"],
                service=item.get("service"),
                state=item["state"],
                cve_id=item.get("cve_id"),
                cvss_score=item.get("cvss_score"),
                severity=item.get("severity"),
                confidence=item.get("confidence", 0.86),
                evidence=item.get("evidence"),
                remediation=item.get("remediation"),
                compliance_map=item.get("compliance_map", []),
                finding_metadata=metadata,
            )
        )

    scan.result_summary = {
        **scan.result_summary,
        "finding_count": len(correlated_findings),
        "sources": [scan.tool],
        "target": scan.target,
        "correlation_sources": ["OSV", "NVD", "MITRE CVE", "Greenbone Community Feed", "NASL", "Snyk Security Database"],
        "ingested": True,
    }


def replace_scan_findings(db: Session, scan: Scan, normalized_findings: list[dict[str, Any]]) -> Scan:
    db.query(Finding).filter(Finding.scan_id == scan.id).delete()
    scan.result_summary = {**scan.result_summary, "ingested": False}
    db.commit()
    _store_findings(db, scan, normalized_findings)
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


def reprocess_scan_results(db: Session, scan: Scan) -> Scan:
    if scan.tool == "openvas":
        metadata = scan.engine_metadata or {}
        report_id = metadata.get("remote_report_id")
        if not report_id:
          raise RuntimeError("No remote report is available for reprocessing.")
        normalized_findings = OpenVASClient().get_report_results(str(report_id), task_id=str(metadata.get("remote_task_id") or ""))
        replace_scan_findings(db, scan, normalized_findings)
    elif scan.tool == "zap":
        target = (scan.engine_metadata or {}).get("target") or scan.target
        normalized_findings = ZAPClient().normalize_results(ZAPClient().get_alerts(target))
        replace_scan_findings(db, scan, normalized_findings)
    else:
        normalized_findings = _mock_results(scan)
        replace_scan_findings(db, scan, normalized_findings)

    _append_audit_log(db, scan, "scan.reprocess")
    return scan


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


def run_direct_network_scan(db: Session, scan: Scan) -> Scan:
    try:
        scan.status = "running"
        scan.started_at = scan.started_at or datetime.now(timezone.utc)
        scan.progress = "10"
        scan.error_message = "Deep network assessment is running. Evidence collection and correlation may take longer than a quick surface scan."
        scan.engine_metadata = {
            **scan.engine_metadata,
            "engine": "network-db",
            "execution_mode": "direct-correlation",
        }
        db.commit()
        db.refresh(scan)

        def _progress_callback(progress: int, detail: dict[str, Any]) -> None:
            scan.progress = str(progress)
            scan.error_message = detail.get("message")
            scan.engine_metadata = {
                **scan.engine_metadata,
                "assessment_phase": detail.get("phase"),
                "assessment_detail": detail,
            }
            db.commit()
            db.refresh(scan)

        normalized_findings = run_network_assessment(scan.target, progress_callback=_progress_callback)
        scan.progress = "92"
        scan.error_message = "Deep assessment completed evidence collection. Correlating results with the vulnerability catalog."
        db.commit()
        db.refresh(scan)
        _store_findings(db, scan, normalized_findings)
        scan.status = "completed"
        scan.progress = "100"
        scan.finished_at = datetime.now(timezone.utc)
        scan.error_message = None
        scan.engine_metadata = {
            **scan.engine_metadata,
            "execution_mode": "direct-correlation",
            "network_probe_count": len(normalized_findings),
            "scan_depth": "deep",
        }
        db.commit()
        db.refresh(scan)
        return scan
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = f"Direct network assessment failed: {exc}"
        db.commit()
        db.refresh(scan)
        return scan


def launch_zap_scan(db: Session, scan: Scan) -> Scan:
    client = ZAPClient()
    metadata = client.launch_scan(scan.target, scan.profile)

    scan.target = metadata["target"]
    scan.status = "queued"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = "5"
    scan.error_message = None
    scan.engine_metadata = {**scan.engine_metadata, **metadata}
    db.add(
        AuditLog(
            actor=scan.triggered_by or "system",
            action="scan.launch",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"tool": scan.tool, "target": scan.target, "phase": "spider", "remote_task_id": metadata["remote_task_id"]},
        )
    )
    db.commit()
    db.refresh(scan)
    return refresh_zap_scan(db, scan)


def launch_mobsf_scan(db: Session, scan: Scan) -> Scan:
    client = MobSFClient()
    metadata = client.launch_scan(scan.target)
    scan.status = "queued"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = "10"
    scan.error_message = None
    scan.engine_metadata = {**scan.engine_metadata, **metadata, "phase": "upload"}
    db.add(
        AuditLog(
            actor=scan.triggered_by or "system",
            action="scan.launch",
            resource_type="scan",
            resource_id=str(scan.id),
            details={"tool": scan.tool, "target": scan.target, "phase": "upload", "remote_task_id": metadata["remote_task_id"]},
        )
    )
    db.commit()
    db.refresh(scan)
    return scan


def refresh_openvas_scan(db: Session, scan: Scan) -> Scan:
    metadata = scan.engine_metadata or {}
    remote_task_id = metadata.get("remote_task_id")
    if not remote_task_id:
        return scan

    client = OpenVASClient()
    try:
        status = client.get_task_status(remote_task_id)
        report_id = status.get("remote_report_id") or metadata.get("remote_report_id")

        scan.status = status["status"]
        scan.progress = str(status.get("progress", "0"))
        scan.error_message = None
        scan.engine_metadata = {
            **scan.engine_metadata,
            "status_text": status.get("status_text"),
            "remote_report_id": report_id,
        }

        if scan.status == "completed" and report_id and not scan.result_summary.get("ingested"):
            try:
                normalized_findings = client.get_report_results(report_id, task_id=str(remote_task_id))
            except Exception as exc:
                scan.status = "completed"
                scan.error_message = f"Report retrieval pending: {exc}"
                scan.engine_metadata = {
                    **scan.engine_metadata,
                    "report_retry_pending": True,
                }
            else:
                _store_findings(db, scan, normalized_findings)
                scan.finished_at = datetime.now(timezone.utc)
                scan.error_message = None
                scan.engine_metadata = {
                    **scan.engine_metadata,
                    "report_retry_pending": False,
                }
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = str(exc)

    db.commit()
    db.refresh(scan)
    return scan


def refresh_zap_scan(db: Session, scan: Scan) -> Scan:
    client = ZAPClient()
    metadata = scan.engine_metadata or {}
    phase = metadata.get("phase", "spider")
    target = metadata.get("target") or scan.target

    try:
        if phase == "spider":
            spider_scan_id = metadata.get("spider_scan_id")
            if not spider_scan_id:
                raise RuntimeError("ZAP spider scan id is missing.")

            spider_status = client.get_spider_status(str(spider_scan_id))
            spider_progress = spider_status["progress"]
            scan.status = "running"
            scan.progress = str(min(spider_progress, 90))
            scan.error_message = None
            scan.engine_metadata = {**metadata, "phase": "spider", "spider_progress": spider_progress}

            if spider_status["status"] == "completed":
                active_metadata = client.launch_active_scan(target)
                scan.status = "running"
                scan.progress = "92"
                scan.engine_metadata = {
                    **scan.engine_metadata,
                    **active_metadata,
                    "phase": "active",
                    "active_progress": 0,
                }
        elif phase == "active":
            active_scan_id = metadata.get("active_scan_id")
            if not active_scan_id:
                raise RuntimeError("ZAP active scan id is missing.")

            active_status = client.get_active_scan_status(str(active_scan_id))
            active_progress = active_status["progress"]
            mapped_progress = 90 + round(active_progress * 0.1)
            scan.status = "running"
            scan.progress = str(min(mapped_progress, 99))
            scan.error_message = None
            scan.engine_metadata = {**metadata, "phase": "active", "active_progress": active_progress}

            if active_status["status"] == "completed":
                raw_alerts = client.get_alerts(target)
                normalized_findings = client.normalize_results(raw_alerts)
                _store_findings(db, scan, normalized_findings)
                scan.status = "completed"
                scan.progress = "100"
                scan.finished_at = datetime.now(timezone.utc)
                scan.engine_metadata = {
                    **scan.engine_metadata,
                    "phase": "completed",
                    "alert_count": len(raw_alerts),
                }
        elif phase == "completed":
            scan.status = "completed"
            scan.progress = "100"
        else:
            raise RuntimeError(f"Unsupported ZAP scan phase '{phase}'.")
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = str(exc)

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

                report_retry_pending = bool((scan.engine_metadata or {}).get("report_retry_pending"))
                if scan.status in {"failed", "cancelled"}:
                    return
                if scan.status == "completed" and scan.result_summary.get("ingested"):
                    return
                if scan.status == "completed" and not report_retry_pending and not scan.result_summary.get("ingested"):
                    refresh_openvas_scan(db, scan)
                    scan = db.get(Scan, scan_id)
                    if scan and scan.result_summary.get("ingested"):
                        return

                if scan.status == "paused":
                    time.sleep(10)
                    continue

                if not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(scan)

                remote_task_id = (scan.engine_metadata or {}).get("remote_task_id")

                if not remote_task_id:
                    try:
                        launch_openvas_scan(db, scan)
                    except RuntimeError as exc:
                        _append_audit_log(
                            db,
                            scan,
                            "scan.fallback",
                            {"tool": scan.tool, "reason": str(exc), "mode": "direct-correlation"},
                        )
                        run_direct_network_scan(db, scan)
                        return
                    else:
                        scan = db.get(Scan, scan_id)
                        if scan and scan.status == "completed" and scan.result_summary.get("ingested"):
                            return
                else:
                    refresh_openvas_scan(db, scan)
                    scan = db.get(Scan, scan_id)
                    if scan and (scan.status == "cancelled" or (scan.status == "completed" and scan.result_summary.get("ingested"))):
                        return
            finally:
                db.close()

            time.sleep(30)
    finally:
        with _worker_lock:
            _active_workers.discard(scan_id)


def _background_zap_worker(scan_id: str) -> None:
    try:
        for _ in range(180):
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if not scan:
                    return

                if scan.status in {"completed", "failed", "cancelled"}:
                    return

                if scan.status == "paused":
                    time.sleep(5)
                    continue

                if not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(scan)

                metadata = scan.engine_metadata or {}
                if not metadata.get("spider_scan_id") and not metadata.get("active_scan_id"):
                    try:
                        launch_zap_scan(db, scan)
                    except Exception as exc:
                        _set_scan_state(db, scan, status="failed", progress="0", error_message=str(exc))
                else:
                    refresh_zap_scan(db, scan)

                scan = db.get(Scan, scan_id)
                if scan and scan.status in {"completed", "failed", "cancelled"}:
                    return
            finally:
                db.close()

            time.sleep(10)
    finally:
        with _worker_lock:
            _active_workers.discard(scan_id)


def _background_mobsf_worker(scan_id: str) -> None:
    try:
        for _ in range(30):
            db = SessionLocal()
            try:
                scan = db.get(Scan, scan_id)
                if not scan:
                    return
                if scan.status in {"completed", "failed", "cancelled"}:
                    return
                if scan.status == "paused":
                    time.sleep(5)
                    continue

                if not scan.started_at:
                    scan.started_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(scan)

                metadata = scan.engine_metadata or {}
                phase = metadata.get("phase", "queued")
                if not metadata.get("remote_task_id"):
                    launch_mobsf_scan(db, scan)
                elif phase == "upload":
                    scan.status = "running"
                    scan.progress = "45"
                    scan.error_message = None
                    scan.engine_metadata = {**metadata, "phase": "analysis"}
                    db.commit()
                    db.refresh(scan)
                elif phase == "analysis":
                    scan.status = "running"
                    scan.progress = "80"
                    scan.error_message = None
                    normalized_findings = _mock_results(scan)
                    _store_findings(db, scan, normalized_findings)
                    scan.status = "completed"
                    scan.progress = "100"
                    scan.finished_at = datetime.now(timezone.utc)
                    scan.engine_metadata = {**metadata, "phase": "completed"}
                    db.commit()
                    db.refresh(scan)
                    return
            finally:
                db.close()
            time.sleep(5)
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


def enqueue_mobsf_scan(scan_id: str) -> None:
    with _worker_lock:
        if scan_id in _active_workers:
            return
        _active_workers.add(scan_id)

    worker = threading.Thread(
        target=_background_mobsf_worker,
        args=(scan_id,),
        daemon=True,
        name=f"mobsf-scan-{scan_id}",
    )
    worker.start()


def pause_scan(db: Session, scan: Scan) -> Scan:
    if scan.status in {"completed", "failed", "cancelled"}:
        return scan
    _set_scan_state(
        db,
        scan,
        status="paused",
        error_message="Assessment paused. Resume when you are ready to continue.",
    )
    _append_audit_log(db, scan, "scan.pause")
    return scan


def resume_scan(db: Session, scan: Scan) -> Scan:
    if scan.status != "paused":
        return scan

    metadata = scan.engine_metadata or {}
    remote_task_id = metadata.get("remote_task_id")
    next_status = "queued" if remote_task_id else "waiting"
    if scan.tool == "zap":
        message = None if remote_task_id else "Web engine queued. Spidering and active scanning will begin automatically in the background."
    elif scan.tool == "mobsf":
        message = None if remote_task_id else "Mobile engine queued. Static analysis will begin automatically in the background."
    else:
        message = None if remote_task_id else "Network engine queued. Discovery will begin automatically in the background."
    _set_scan_state(db, scan, status=next_status, error_message=message)
    _append_audit_log(db, scan, "scan.resume")

    if scan.tool == "openvas":
        enqueue_openvas_scan(str(scan.id))
    elif scan.tool == "zap":
        enqueue_zap_scan(str(scan.id))
    elif scan.tool == "mobsf":
        enqueue_mobsf_scan(str(scan.id))
    return scan


def cancel_scan(db: Session, scan: Scan) -> Scan:
    if scan.status in {"completed", "failed", "cancelled"}:
        return scan

    remote_task_id = (scan.engine_metadata or {}).get("remote_task_id")
    if scan.tool == "openvas" and remote_task_id:
        OpenVASClient().stop_task(str(remote_task_id))

    _set_scan_state(
        db,
        scan,
        status="cancelled",
        error_message="Assessment cancelled by operator.",
    )
    scan.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    _append_audit_log(db, scan, "scan.cancel")
    return scan


def enqueue_zap_scan(scan_id: str) -> None:
    with _worker_lock:
        if scan_id in _active_workers:
            return
        _active_workers.add(scan_id)

    worker = threading.Thread(
        target=_background_zap_worker,
        args=(scan_id,),
        daemon=True,
        name=f"zap-scan-{scan_id}",
    )
    worker.start()
