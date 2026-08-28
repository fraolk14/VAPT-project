import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.agent import AgentDevice, AgentEnrollmentToken, SoftwareAllowlist
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.orchestrator import _store_findings, _upsert_asset_from_finding

router = APIRouter(prefix="/agent", tags=["Windows Endpoint Agent"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Agent payload schemas
class EnrollRequest(BaseModel):
    token: str
    hostname: str
    hardware_id: str | None = None
    os_info: str | None = None


class EnrollResponse(BaseModel):
    device_id: str
    agent_key: str
    checkin_interval_sec: int = 14400  # Default 4 hours


class TokenGenerateRequest(BaseModel):
    created_by: str | None = "admin"
    ttl_hours: int = 72


class TokenGenerateResponse(BaseModel):
    token: str
    created_at: datetime
    expires_at: datetime


class AssetFactPayload(BaseModel):
    hostname: str
    domain: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    architecture: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    cpu_info: str | None = None
    ram_gb: float | None = None
    disk_total_gb: float | None = None
    disk_free_gb: float | None = None
    ip_addresses: list[str] = []
    mac_addresses: list[str] = []
    username: str | None = None
    user_domain: str | None = None
    user_sid: str | None = None
    installed_patches: list[str] = []
    bitlocker_status: str | None = None
    antivirus_status: str | None = None
    firewall_status: str | None = None


class CheckinRequest(BaseModel):
    agent_id: str
    collected_at: datetime
    asset: AssetFactPayload
    software_inventory: list[dict[str, Any]] = []
    misconfigurations: list[dict[str, Any]] = []
    shadow_it_flags: list[dict[str, Any]] = []


def get_preferred_physical_ip(ip_list: list[str] | None = None, fallback_ip: str | None = None) -> str:
    """
    Extract the real physical LAN/WAN IP address from endpoint reported facts.
    Prioritizes real physical LAN subnets (192.168.x.x, 10.x.x.x)
    while discarding Docker bridge (172.17.x, 172.18.x, 172.19.x, 172.20.x), loopback, and APIPA.
    """
    candidates = []
    for ip in (ip_list or []):
        ip_str = str(ip).strip()
        if not ip_str or ip_str in {"0.0.0.0", "Unknown IP", "127.0.0.1", "localhost"}:
            continue
        if ip_str.startswith("127.") or ip_str.startswith("169.254."):
            continue
        # Discard Docker and virtual bridge subnets
        if ip_str.startswith(("172.17.", "172.18.", "172.19.", "172.20.")):
            continue
        candidates.append(ip_str)

    def ip_rank(ip_str: str) -> int:
        if ip_str.startswith("192.168."):
            return 100
        if ip_str.startswith("10."):
            return 90
        if ip_str.startswith("172."):
            return 50
        return 10

    if candidates:
        candidates.sort(key=ip_rank, reverse=True)
        return candidates[0]

    # Check fallback_ip
    if fallback_ip:
        fb = str(fallback_ip).strip()
        if fb and not fb.startswith(("172.17.", "172.18.", "172.19.", "172.20.", "127.", "169.254.", "0.0.0.0", "Unknown IP")):
            return fb

    return ip_list[0] if (ip_list and len(ip_list) > 0) else (fallback_ip or "127.0.0.1")


@router.post("/enroll", response_model=EnrollResponse)
def enroll_agent_device(request: Request, payload: EnrollRequest, db: Session = Depends(get_db)):
    """Single-use enrollment token bootstrap trust endpoint."""
    token_entry = db.query(AgentEnrollmentToken).filter(
        AgentEnrollmentToken.token == payload.token.strip()
    ).first()

    if not token_entry or token_entry.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or previously used enrollment token.",
        )

    if token_entry.expires_at and token_entry.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has expired.",
        )

    # Invalidate token so it cannot be reused (Single-Use Requirement)
    token_entry.is_used = True

    # Determine remote client IP from headers or direct socket
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        raw_ip = forwarded_for.split(",")[0].strip()
    else:
        raw_ip = request.client.host if request.client else "Unknown IP"

    client_ip = get_preferred_physical_ip(None, raw_ip)

    device_id = payload.hardware_id.strip() if payload.hardware_id else f"WIN-{secrets.token_hex(4).upper()}"
    raw_agent_key = f"vap_agent_sec_{secrets.token_urlsafe(32)}"
    credential_hash = pwd_context.hash(raw_agent_key)

    device = db.query(AgentDevice).filter(AgentDevice.device_id == device_id).first()
    if not device:
        device = AgentDevice(
            device_id=device_id,
            hostname=payload.hostname,
            hardware_id=payload.hardware_id,
            credential_hash=credential_hash,
            enrollment_token_ref=payload.token,
            status="active",
            ip_address=client_ip,
            os_info=payload.os_info,
        )
        db.add(device)
    else:
        device.credential_hash = credential_hash
        device.status = "active"
        device.hostname = payload.hostname
        device.ip_address = client_ip
        device.last_seen = datetime.now(timezone.utc)

    # Immediately upsert Asset record so device appears on Assets page instantly upon enrollment
    asset_obj = db.query(Asset).filter(
        (Asset.hostname == payload.hostname) | (Asset.asset_name == payload.hostname)
    ).first()
    if not asset_obj:
        asset_obj = Asset(
            asset_name=payload.hostname,
            hostname=payload.hostname,
            ip_address=client_ip if client_ip != "Unknown IP" else "Enrolled Agent",
            os=payload.os_info or "Windows Endpoint",
            asset_type="Endpoint Workstation",
            environment="prod",
            criticality="medium",
            exposure="internal",
            tags=["managed-agent", "vap-agent-active"],
            business_unit="IT Workstation Fleet",
            risk_score=5.0,
        )
        db.add(asset_obj)
    else:
        if client_ip and client_ip != "Unknown IP":
            asset_obj.ip_address = client_ip

    db.commit()
    db.refresh(device)

    return EnrollResponse(
        device_id=device.device_id,
        agent_key=raw_agent_key,
        checkin_interval_sec=14400,
    )


import traceback

@router.post("/checkin")
def agent_checkin(
    payload: CheckinRequest,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Periodic agent checkin ingestion with per-device key auth and revocation check."""
    try:
        # Find matching device
        device = db.query(AgentDevice).filter(AgentDevice.device_id == payload.agent_id).first()
        if not device:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown agent device.")

        if not pwd_context.verify(x_agent_key, device.credential_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credential.")

        if device.status == "revoked":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent device credential has been revoked.")

        # Resolve real physical adapter IP (excluding Docker/virtual bridge subnets)
        raw_client_ip = request.client.host if (request and request.client) else None
        primary_ip = get_preferred_physical_ip(payload.asset.ip_addresses, raw_client_ip)

        device.last_seen = datetime.now(timezone.utc)
        device.ip_address = primary_ip

        if payload.asset.os_name:
            device.os_info = f"{payload.asset.os_name} {payload.asset.os_version or ''}".strip()

        # 1. Upsert Device Asset Facts into PostgreSQL Asset table
        asset_obj = db.query(Asset).filter(
            (Asset.hostname == payload.asset.hostname) | (Asset.ip_address == primary_ip)
        ).first()


        owner_str = f"{payload.asset.user_domain}\\{payload.asset.username}" if payload.asset.user_domain and payload.asset.username else payload.asset.username

        if not asset_obj:
            asset_obj = Asset(
                asset_name=payload.asset.hostname,
                hostname=payload.asset.hostname,
                ip_address=primary_ip,
                os=payload.asset.os_name,
                asset_type="Endpoint Workstation",
                environment="prod",
                criticality="medium",
                owner=owner_str,
                exposure="internal",
                tags=["managed-agent", "vap-agent-active"],
                business_unit="IT Workstation Fleet",
                risk_score=5.0,
            )
            db.add(asset_obj)
        else:
            asset_obj.hostname = payload.asset.hostname
            asset_obj.ip_address = primary_ip
            if payload.asset.os_name:
                asset_obj.os = payload.asset.os_name
            if owner_str:
                asset_obj.owner = owner_str
            asset_obj.tags = list(set((asset_obj.tags or []) + ["managed-agent", "vap-agent-active"]))
        db.flush()

        # Create dummy scan record to associate agent findings for deduplication
        scan = Scan(
            scan_name=f"Endpoint Checkin - {payload.asset.hostname}",
            scan_type="endpoint",
            tool="endpoint-agent",
            target=primary_ip,
            status="completed",
            progress="100",
        )
        db.add(scan)
        db.flush()

        normalized_findings = []

        # 2. Process Misconfigurations
        for mc in payload.misconfigurations:
            normalized_findings.append({
                "title": mc.get("title") or "Endpoint Misconfiguration",
                "category": "Misconfiguration",
                "source": "endpoint-agent",
                "port": 0,
                "protocol": "local",
                "service": "Windows Host",
                "state": "open",
                "severity": mc.get("severity", "medium"),
                "cvss_score": mc.get("cvss_score", 5.0),
                "cve_id": mc.get("cis_control"),
                "evidence": f"Endpoint: {payload.asset.hostname}\nSetting: {mc.get('title')}\nEvidence: {mc.get('evidence')}",
                "remediation": mc.get("remediation") or "Remediate local security configuration according to CIS Benchmark.",
                "compliance_map": mc.get("compliance_map") or ["CIS Windows Benchmark", "NIST SP 800-53"],
                "finding_metadata": {
                    "hostname": payload.asset.hostname,
                    "ip_address": primary_ip,
                    "user_sid": payload.asset.user_sid,
                    "bitlocker": payload.asset.bitlocker_status,
                    "defender": payload.asset.antivirus_status,
                    "check_key": mc.get("check_key"),
                },
            })

        # 3. Process Shadow IT & Full Software Inventory against Allowlist and Governance tables
        from app.services.software_discovery import process_software_governance
        allowlist_names = {item.name.lower() for item in db.query(SoftwareAllowlist).all()}
        
        for sw in payload.software_inventory:
            sw_name = sw.get("name")
            if not sw_name:
                continue

            # Ingest into Software & SoftwareAsset governance tables (batch processing)
            process_software_governance(
                db,
                software_name=sw_name,
                vendor=sw.get("vendor"),
                version=sw.get("version"),
                category=sw.get("category") or "Application",
                asset_id=str(asset_obj.id) if asset_obj else None,
                installed_path=sw.get("install_location"),
                ip_address=primary_ip,
                hostname=payload.asset.hostname,
                endpoint_name=payload.asset.hostname,
                source="VAP Endpoint Agent",
                commit=False,
                query_nvd=False,
            )


            # Generate security finding for unapproved software drift
            if allowlist_names and sw_name.lower() not in allowlist_names:
                normalized_findings.append({
                    "title": f"Unauthorized Software Drift: {sw_name}",
                    "category": "Shadow IT",
                    "source": "endpoint-agent",
                    "port": 0,
                    "protocol": "local",
                    "service": "Software Inventory",
                    "state": "open",
                    "severity": "high" if sw.get("category") == "RemoteAccess" else "medium",
                    "cvss_score": 6.5,
                    "cve_id": None,
                    "evidence": f"Unsanctioned software '{sw_name}' (Version: {sw.get('version')}) installed on {payload.asset.hostname}.",
                    "remediation": "Uninstall unapproved application or add it to the corporate Software Allowlist policy.",
                    "compliance_map": ["ISO 27001 A.12.6.2", "CIS Control 2.1"],
                    "finding_metadata": {
                        "hostname": payload.asset.hostname,
                        "software_name": sw_name,
                        "version": sw.get("version"),
                        "vendor": sw.get("vendor"),
                        "install_location": sw.get("install_location"),
                    },
                })

        for flag in payload.shadow_it_flags:
            normalized_findings.append({
                "title": flag.get("title") or "Shadow IT Finding",
                "category": "Shadow IT",
                "source": "endpoint-agent",
                "port": 0,
                "protocol": "local",
                "service": "System Inspection",
                "state": "open",
                "severity": flag.get("severity", "high"),
                "cvss_score": 7.0,
                "cve_id": None,
                "evidence": f"Endpoint: {payload.asset.hostname}\nFlag: {flag.get('title')}\nDetails: {flag.get('evidence')}",
                "remediation": flag.get("remediation") or "Review unauthorized tool or storage client and enforce policy.",
                "compliance_map": ["CIS Control 2.3", "NIST CSF PR.DS-1"],
                "finding_metadata": {
                    "hostname": payload.asset.hostname,
                    "ip_address": primary_ip,
                    "tool_type": flag.get("type"),
                },
            })

        # Store normalized findings using standard platform deduplication
        if normalized_findings:
            _store_findings(db, scan, normalized_findings)

        db.commit()
        return {"status": "success", "processed_findings": len(normalized_findings)}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Checkin error: {str(e)}")


# Admin Token & Device Management Endpoints
@router.post("/tokens/generate", response_model=TokenGenerateResponse)
def generate_enrollment_token(payload: TokenGenerateRequest, db: Session = Depends(get_db)):
    """Generate a single-use agent enrollment token."""
    raw_token = f"vap_tok_{secrets.token_hex(16)}"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=payload.ttl_hours)

    entry = AgentEnrollmentToken(
        token=raw_token,
        created_by=payload.created_by,
        is_used=False,
        expires_at=expires_at,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    return TokenGenerateResponse(
        token=entry.token,
        created_at=entry.created_at,
        expires_at=entry.expires_at,
    )


@router.get("/devices")
def list_agent_devices(db: Session = Depends(get_db)):
    """List all registered agent devices."""
    devices = db.query(AgentDevice).order_by(AgentDevice.last_seen.desc()).all()
    return [
        {
            "id": str(d.id),
            "device_id": d.device_id,
            "hostname": d.hostname,
            "hardware_id": d.hardware_id,
            "status": d.status,
            "ip_address": d.ip_address,
            "os_info": d.os_info,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
        }
        for d in devices
    ]


@router.post("/devices/{device_id}/revoke")
def revoke_agent_device(device_id: str, db: Session = Depends(get_db)):
    """Revoke an agent device credential immediately blocking subsequent checkins."""
    device = db.query(AgentDevice).filter(AgentDevice.device_id == device_id).first()
    if not device:
        try:
            device = db.query(AgentDevice).filter(AgentDevice.id == uuid.UUID(device_id)).first()
        except Exception:
            pass

    if not device:
        raise HTTPException(status_code=404, detail="Agent device not found.")

    device.status = "revoked"
    db.commit()
    return {"status": "success", "message": f"Device '{device.hostname}' credential has been revoked."}


@router.get("/download")
def download_agent_binary():
    """Download the compiled Go Windows Endpoint Agent static executable."""
    search_paths = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "bin", "vap-agent.exe")),
        "/app/bin/vap-agent.exe",
    ]
    binary_path = None
    for path in search_paths:
        if os.path.exists(path):
            binary_path = path
            break

    if not binary_path:
        raise HTTPException(status_code=404, detail="Agent binary not yet compiled. Run build script.")
    headers = {"Content-Disposition": 'attachment; filename="vap-agent.exe"'}
    return FileResponse(binary_path, filename="vap-agent.exe", media_type="application/octet-stream", headers=headers)


@router.get("/installer-script")
def download_installer_script(token: str = Query(default="YOUR_ENROLLMENT_TOKEN")):
    """Generate GPO / Intune PowerShell installation script for silent deployment."""
    ps_content = f"""# VAP Windows Endpoint Agent - GPO / Intune Deployment Script
$ErrorActionPreference = "Stop"

$BackendUrl = "http://localhost:18080"
$EnrollmentToken = "{token}"
$InstallDir = "$env:ProgramFiles\\VAP\\Agent"
$ExePath = "$InstallDir\\vap-agent.exe"

Write-Host "Creating installation directory at $InstallDir..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "Downloading VAP Agent binary..."
Invoke-WebRequest -Uri "$BackendUrl/api/agent/download" -OutFile $ExePath

Write-Host "Enrolling endpoint with VAP platform..."
& "$ExePath" enroll --url "$BackendUrl" --token "$EnrollmentToken"

Write-Host "Installing VAP Windows Service..."
& "$ExePath" install

Write-Host "Starting VAP Windows Service..."
& "$ExePath" start

Write-Host "VAP Windows Endpoint Agent successfully deployed."
"""
    return Response(content=ps_content, media_type="text/plain", headers={"Content-Disposition": "attachment; filename=install-agent.ps1"})
