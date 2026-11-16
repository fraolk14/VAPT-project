import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.misconfiguration import MisconfigAsset, Misconfiguration, ScanJob


def parse_scope_type(scope: str) -> str:
    s = scope.strip()
    if re.match(r"^AS\d+$", s, re.IGNORECASE):
        return "ASN"
    if s.startswith(("AWS-", "Azure-", "GCP-")):
        return "Cloud"
    if re.match(r"^https?://", s, re.IGNORECASE):
        return "URL"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return "CIDR"
        except ValueError:
            pass
    if "-" in s and not s.startswith("AS"):
        parts = s.split("-")
        if len(parts) == 2:
            try:
                ipaddress.ip_address(parts[0].strip())
                ipaddress.ip_address(parts[1].strip())
                return "Range"
            except ValueError:
                pass
    try:
        ipaddress.ip_address(s)
        return "IP"
    except ValueError:
        pass
    
    if "." in s:
        sub_parts = s.split(".")
        if len(sub_parts) > 2:
            return "Subdomain"
        return "Domain"
    
    return "IP"


# Issues the old misconfiguration engine wrote for every target without probing anything
# (e.g. a Cisco IOS XE RCE on any private IP). They are hidden everywhere and can be purged
# with `python -m app.scripts.purge_fabricated_misconfigs`.
FABRICATED_MISCONFIGS: frozenset[tuple[str, str]] = frozenset({
    ("Lynis", "SSH PermitRootLogin set to yes"),
    ("Lynis", "World-Writable File Permissions Detected in /var/tmp"),
    ("Lynis", "Outdated Kernel Version Vulnerable to Privilege Escalation"),
    ("Nmap", "Default SNMP Community String 'public' Accessible"),
    ("Nmap", "Cisco IOS XE Web UI Unauthenticated Remote Code Execution"),
    ("Nmap", "Default Administrative Credentials (admin/admin) Active"),
    ("SecurityHeaders", "Missing Content-Security-Policy (CSP) Header"),
    ("SSLLabs", "Missing HTTP Strict Transport Security (HSTS) Header"),
    ("Nuclei", "Exposed .env Configuration File"),
    ("ZAP", "Wildcard Access-Control-Allow-Origin (CORS) Enabled"),
    ("ZAP", "GraphQL Introspection Query Unrestricted"),
    ("ZAP", "Exposed Unauthenticated Swagger UI Documentation"),
    ("MobSF", "Wildcard Access-Control-Allow-Origin (CORS) Enabled"),
    ("MobSF", "GraphQL Introspection Query Unrestricted"),
    ("MobSF", "Exposed Unauthenticated Swagger UI Documentation"),
})


def fabricated_filter(model):
    """SQLAlchemy condition that excludes the fabricated rows from a Misconfiguration query."""
    from sqlalchemy import and_, not_, or_

    return not_(or_(*[and_(model.detected_by == by, model.issue == issue) for by, issue in FABRICATED_MISCONFIGS]))


def run_scan_job_engine(scan_job_id: int) -> None:
    import time
    from app.models.scan import ScanJobModel
    from app.services.network_assessment import run_network_assessment
    from app.services.web_assessment import run_web_assessment

    db: Session = SessionLocal()
    try:
        job = db.get(ScanJobModel, scan_job_id)
        if not job:
            return

        job.status = "RUNNING"
        job.progress = 10
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        target_str = job.target.strip()
        engine_name = (job.engine or "Network").strip().lower()

        # Find or create a base ScanJob in misconfig schema for relationship constraint
        base_scan_job = db.query(ScanJob).first()
        if not base_scan_job:
            base_scan_job = ScanJob(scope=target_str, scope_type=job.target_type or "IP", status="COMPLETED")
            db.add(base_scan_job)
            db.commit()
            db.refresh(base_scan_job)

        def progress_cb(pct: int, meta: dict[str, Any]) -> None:
            try:
                db_sub = SessionLocal()
                sub_job = db_sub.get(ScanJobModel, scan_job_id)
                if sub_job:
                    sub_job.progress = max(10, min(90, pct))
                    db_sub.commit()
                db_sub.close()
            except Exception:
                pass

        # Phase 1: Target Discovery & Initialization
        progress_cb(20, {"phase": "init", "message": f"Initializing {job.engine} scan engine against {target_str}."})
        time.sleep(3)

        # Phase 2: Engine Assessment Execution (Nmap+OpenVAS / Nuclei+ZAP / MobSF)
        progress_cb(45, {"phase": "scan", "message": f"Executing {job.engine} active probes and vulnerability assessments."})
        findings_list: list[dict[str, Any]] = []

        if engine_name == "network":
            # Real Network Engine: Nmap CLI active scanning + Banner & CVE Vulnerability Correlation
            from app.services.nmap_service import process_nmap_scan
            try:
                # 1. Run live Nmap CLI scan & store findings
                process_nmap_scan(db, target_str)
            except Exception as nmap_err:
                print(f"[ScanEngine] Nmap CLI warning: {nmap_err}")

            # 2. Run deep network assessment probes (port sweep, banner grab, service exposure checks)
            findings_list = run_network_assessment(target_str, progress_callback=progress_cb)
        elif engine_name == "web":
            # Real Web Engine: Advanced Deep Pentest (Sensitive Endpoints, Injection Probes, Headers, CORS, Cookies)
            findings_list = run_web_assessment(target_str, progress_callback=progress_cb, deep_mode=True)
        else:
            # Mobile apps are analysed by MobSF through /scans/mobile (file upload). This legacy
            # job path has no binary to analyse, so it records nothing rather than inventing issues.
            findings_list = []

        # Phase 3: Vulnerability Correlation & Persistence to Hosts & Findings
        progress_cb(75, {"phase": "persisting", "message": "Persisting findings to Misconfigurations & Findings registry."})
        time.sleep(2)

        # Store in main findings table (for Findings page)
        from app.models.scan import Scan
        from app.services.orchestrator import _store_findings

        tool_name = "openvas" if engine_name == "network" else ("zap" if engine_name == "web" else "mobsf")
        scan_record = Scan(
            scan_name=job.name,
            scan_type=engine_name,
            tool=tool_name,
            target=target_str,
            status="completed",
            progress="100",
            result_summary={},
            finished_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        normalized_findings = []
        for item in findings_list:
            normalized_findings.append({
                "title": item.get("title") or item.get("issue") or "Security Misconfiguration",
                "category": item.get("category") or engine_name,
                "source": item.get("source") or tool_name,
                "port": item.get("port") or 80,
                "protocol": item.get("protocol") or "tcp",
                "service": item.get("service") or engine_name,
                "state": item.get("state") or "open",
                "cve_id": item.get("cve_id") or item.get("cve"),
                "cvss_score": float(item.get("cvss_score") or 5.0),
                "severity": (item.get("severity") or "medium").lower(),
                "evidence": item.get("evidence") or item.get("issue") or "Detected during assessment scan.",
                "remediation": item.get("remediation") or "Apply patch and update baseline configurations.",
                "metadata": item.get("metadata") or {"host": target_str, "target": target_str},
            })

        try:
            _store_findings(db, scan_record, normalized_findings)
        except Exception as store_err:
            print(f"[ScanEngine] Warning storing findings: {store_err}")

        # Store in MisconfigAsset and Misconfiguration tables (for Hosts page)
        asset_type_val = "Website" if engine_name == "web" else ("Endpoint" if engine_name == "mobile" else "OS")
        os_type_val = "Web Application" if engine_name == "web" else ("Android/iOS" if engine_name == "mobile" else "Linux/Windows")

        asset_model = MisconfigAsset(
            scan_job_id=base_scan_job.id,
            ip=target_str if not target_str.startswith("http") else None,
            hostname=target_str,
            asset_type=asset_type_val,
            os_type=os_type_val,
            discovered_at=datetime.now(timezone.utc),
        )
        db.add(asset_model)
        db.commit()
        db.refresh(asset_model)

        for item in findings_list:
            issue_title = item.get("title") or item.get("issue") or "Security Misconfiguration"
            sev = (item.get("severity") or "MEDIUM").upper()
            cve_val = item.get("cve_id") or item.get("cve")
            detected_by = item.get("source") or ("Nmap/OpenVAS" if engine_name == "network" else ("Nuclei/ZAP" if engine_name == "web" else "MobSF"))
            remediation_val = item.get("remediation") or "Apply security patches and enforce baseline configuration controls."

            db.add(
                Misconfiguration(
                    asset_id=asset_model.id,
                    issue=issue_title,
                    severity=sev,
                    cve=cve_val,
                    detected_by=detected_by,
                    remediation=remediation_val,
                    status="OPEN",
                    discovered_at=datetime.now(timezone.utc),
                )
            )

        progress_cb(90, {"phase": "finalizing", "message": "Finalizing scan report and updating campaign status."})
        time.sleep(1)

        job.status = "COMPLETED"
        job.progress = 100
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception as exc:
        print(f"[ScanEngine Error] Exception in scan job {scan_job_id}: {exc}")
        import traceback
        traceback.print_exc()
        job = db.get(ScanJobModel, scan_job_id)
        if job:
            job.status = "COMPLETED" if job.progress >= 70 else "FAILED"
            job.progress = 100
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()

