import logging
import os
import re
import socket
import subprocess

from datetime import datetime, timezone
import requests

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.software import Software, SoftwareAsset, WhitelistSoftware

logger = logging.getLogger(__name__)
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# In-memory CVE cache to eliminate redundant NVD API latency
NVD_CACHE: dict[str, tuple[list[str], float]] = {}


def is_host_responsive(host: str, timeout: float = 0.4) -> bool:
    """Quick 0.4s pre-flight check to see if host has any listening ports before running full scanner."""
    probe_ports = [80, 443, 22, 135, 445, 8080, 8000, 3306, 5432, 21, 25]
    for port in probe_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def query_nvd_for_cves(software_name: str, version: str | None = None) -> tuple[list[str], float]:
    """
    Query real NVD API for CVEs matching software name and optional version with fast in-memory caching.
    Returns (list of cve_ids, highest_risk_score).
    """
    cache_key = f"{software_name}:{version or ''}".strip().lower()
    if cache_key in NVD_CACHE:
        return NVD_CACHE[cache_key]

    cve_ids: list[str] = []
    max_cvss: float = 0.0
    try:
        query = f"{software_name} {version}".strip() if version else software_name
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        response = requests.get(
            NVD_API_URL,
            params={"keywordSearch": query, "resultsPerPage": 5},
            headers=headers,
            timeout=2.0,
        )
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id")
                if cve_id:
                    cve_ids.append(cve_id)
                metrics = cve_obj.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                if cvss_v3:
                    score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0.0)
                    if score > max_cvss:
                        max_cvss = float(score)
    except Exception as exc:
        logger.debug("NVD API lookup note for %s: %s", software_name, exc)
    
    result = (cve_ids, max_cvss)
    NVD_CACHE[cache_key] = result
    return result


def run_wmi_discovery(host: str) -> list[dict]:
    """Execute real WMI subprocess discovery against Windows endpoint."""
    discovered = []
    try:
        cmd = [
            "wmic",
            f"/node:{host}",
            "product",
            "get",
            "Name,Vendor,Version,InstallLocation",
            "/format:csv",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
            for line in lines[1:]:
                parts = line.split(",")
                if len(parts) >= 4 and parts[1]:
                    discovered.append({
                        "name": parts[1],
                        "vendor": parts[2] if len(parts) > 2 else None,
                        "version": parts[3] if len(parts) > 3 else None,
                        "installed_path": parts[0] if len(parts) > 0 else None,
                        "category": "OS",
                    })
    except Exception as exc:
        logger.debug("WMI discovery execution note for %s: %s", host, exc)
    return discovered


def run_nmap_service_discovery(host: str) -> list[dict]:
    """Execute fast Nmap / socket service version discovery against target host."""
    discovered = []

    # Quick pre-flight check to skip offline hosts instantly
    if not is_host_responsive(host, timeout=0.3):
        return []

    try:
        cmd = ["nmap", "-sV", "--version-light", "-T4", "-F", "--open", "--host-timeout", "4s", host]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if "/tcp" in line or "/udp" in line:
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 3 and "open" in parts[1]:
                        port = parts[0]
                        svc_name = parts[2]
                        version_info = " ".join(parts[3:]) if len(parts) > 3 else "1.0"
                        if svc_name and svc_name != "unknown":
                            discovered.append({
                                "name": f"{svc_name.title()} Service ({port})",
                                "vendor": svc_name.title(),
                                "version": version_info or "1.0",
                                "category": "Network",
                            })
    except Exception as exc:
        logger.debug("Nmap service discovery note for %s: %s", host, exc)

    # Socket Banner Probing fallback if nmap is unreachable or blocked
    if not discovered:
        common_ports = [
            (80, "HTTP Web Server", "Web"),
            (443, "HTTPS Web Server", "Web"),
            (22, "SSH Server", "Network"),
            (21, "FTP Server", "Network"),
            (25, "SMTP Mail Server", "Network"),
            (3306, "MySQL Database Server", "Database"),
            (5432, "PostgreSQL Database Server", "Database"),
            (6379, "Redis Server", "Database"),
            (8000, "FastAPI Web Application", "Web"),
            (8080, "Nginx / Web Proxy Server", "Web"),
        ]
        for port, service_label, category in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = s.recv(256)
                        if data:
                            banner = data.decode(errors="ignore").splitlines()[0]
                    except Exception:
                        pass
                    s.close()
                    discovered.append({
                        "name": f"{service_label} (Port {port})",
                        "vendor": service_label.split()[0],
                        "version": banner[:40] if banner else "Detected",
                        "category": category,
                    })
            except Exception:
                pass
    return discovered



def process_software_governance(
    db: Session,
    software_name: str,
    vendor: str | None,
    version: str | None,
    category: str,
    asset_id: str | None = None,
    installed_path: str | None = None,
    ip_address: str | None = None,
    hostname: str | None = None,
    endpoint_name: str | None = None,
    source: str = "Nmap -sV",
) -> Software:
    """Classify software status (APPROVED, VULNERABLE, UNAUTHORIZED) using whitelist table & NVD CVE API and map network source."""
    # 1. Check Whitelist table
    whitelist_entry = db.query(WhitelistSoftware).filter(WhitelistSoftware.name.ilike(f"%{software_name}%")).first()
    
    # 2. Query NVD API for CVEs
    cve_ids, risk_score = query_nvd_for_cves(software_name, version)
    
    if whitelist_entry:
        status = "APPROVED"
    elif risk_score >= 7.0 or len(cve_ids) > 0:
        status = "VULNERABLE"
    else:
        status = "UNAUTHORIZED"

    sw = db.query(Software).filter(Software.name == software_name, Software.version == version).first()
    if not sw:
        sw = Software(
            name=software_name,
            vendor=vendor,
            version=version,
            category=category,
            status=status,
            risk_score=risk_score,
            cves=cve_ids,
        )
        db.add(sw)
        db.flush()
    else:
        sw.status = status
        sw.risk_score = max(sw.risk_score, risk_score)
        sw.cves = list(set(sw.cves + cve_ids))
        sw.updated_at = datetime.now(timezone.utc)

    # Always link / record SoftwareAsset network source mapping
    existing_link = None
    if ip_address:
        existing_link = db.query(SoftwareAsset).filter(SoftwareAsset.software_id == sw.id, SoftwareAsset.ip_address == ip_address).first()
    elif asset_id:
        existing_link = db.query(SoftwareAsset).filter(SoftwareAsset.software_id == sw.id, SoftwareAsset.asset_id == asset_id).first()

    if not existing_link:
        sw_asset = SoftwareAsset(
            software_id=sw.id,
            asset_id=asset_id,
            ip_address=ip_address,
            hostname=hostname,
            endpoint_name=endpoint_name or hostname or ip_address,
            source=source,
            installed_path=installed_path,
        )
        db.add(sw_asset)
    else:
        if ip_address:
            existing_link.ip_address = ip_address
        if hostname:
            existing_link.hostname = hostname
        if source:
            existing_link.source = source
        if installed_path:
            existing_link.installed_path = installed_path

    db.commit()
    db.refresh(sw)
    return sw
