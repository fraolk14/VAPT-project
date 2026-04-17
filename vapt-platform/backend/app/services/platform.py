from __future__ import annotations

import hashlib
import secrets
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.platform import DevSecOpsEvent, DevSecOpsHook, PluginRegistration, PublicApiKey
from app.models.scan import Scan


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def create_api_key(db: Session, name: str, role_scope: str) -> tuple[PublicApiKey, str]:
    secret = f"vapt_{secrets.token_urlsafe(24)}"
    key = PublicApiKey(
        name=name,
        key_prefix=secret[:12],
        key_hash=_hash_secret(secret),
        role_scope=role_scope,
        enabled=True,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key, secret


def create_devsecops_hook(
    db: Session,
    name: str,
    provider: str,
    project_name: str,
    target_url: str,
    metadata_json: dict,
) -> tuple[DevSecOpsHook, str]:
    secret = DevSecOpsHook.generate_secret()
    hook = DevSecOpsHook(
        name=name,
        provider=provider,
        project_name=project_name,
        target_url=target_url,
        secret_hash=_hash_secret(secret),
        secret_hint=secret[-6:],
        enabled=True,
        metadata_json=metadata_json,
    )
    db.add(hook)
    db.commit()
    db.refresh(hook)
    return hook, secret


def verify_hook_secret(hook: DevSecOpsHook, provided_secret: str | None) -> bool:
    if not hook.enabled or not provided_secret:
        return False
    return hook.secret_hash == _hash_secret(provided_secret)


def record_devsecops_event(
    db: Session,
    hook: DevSecOpsHook,
    payload: dict,
) -> DevSecOpsEvent:
    findings_payload = payload.get("findings", [])
    scan = Scan(
        scan_name=f"{hook.project_name} Pipeline Gate",
        scan_type="pipeline",
        tool=hook.provider,
        status="completed",
        target=hook.target_url,
        profile="ci",
        progress="100",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        result_summary={"ingested_findings": len(findings_payload), "provider": hook.provider},
        engine_metadata={"ingestion": "devsecops-hook", "project_name": hook.project_name},
    )
    db.add(scan)
    db.flush()

    ingested_count = 0
    for item in findings_payload:
        finding = Finding(
            scan_id=scan.id,
            title=item.get("title", "Pipeline security finding"),
            category=item.get("category", "pipeline"),
            source=hook.provider,
            status=item.get("status", "open"),
            port=int(item.get("port", 0) or 0),
            protocol=item.get("protocol", "pipeline"),
            service=item.get("service", "ci"),
            state="open",
            cve_id=item.get("cve_id"),
            cvss_score=item.get("cvss_score"),
            severity=item.get("severity", "medium"),
            confidence=float(item.get("confidence", 0.75) or 0.75),
            evidence=item.get("evidence"),
            remediation=item.get("remediation"),
            compliance_map=item.get("compliance_map", ["OWASP ASVS"]),
            finding_metadata={
                "pipeline": payload.get("pipeline", {}),
                "raw": item,
            },
        )
        db.add(finding)
        ingested_count += 1

    event = DevSecOpsEvent(
        hook_id=hook.id,
        event_type=payload.get("event_type", "pipeline_scan"),
        provider=hook.provider,
        status="processed",
        summary=f"Ingested {ingested_count} finding(s) from {hook.project_name}",
        payload=payload,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def summarize_attack_surface(db: Session) -> dict:
    assets = db.query(Asset).all()
    findings = db.query(Finding).filter(Finding.status != "resolved").all()

    internal_assets = sum(1 for asset in assets if (asset.exposure or "").lower() == "internal")
    external_assets = sum(1 for asset in assets if (asset.exposure or "").lower() == "external")
    web_assets = sum(1 for asset in assets if (asset.asset_type or "").lower() == "web")
    cloud_assets = sum(1 for asset in assets if asset.cloud_provider)
    mobile_assets = sum(1 for asset in assets if (asset.asset_type or "").lower() == "mobile")
    internet_facing_targets = [asset.hostname or asset.ip_address for asset in assets if (asset.exposure or "").lower() == "external"][:8]
    subdomain_candidates = sorted(
        {
            host
            for asset in assets
            for host in [asset.hostname]
            if host and "." in host and not host.replace(".", "").isdigit()
        }
    )[:8]

    exposed_findings = sum(
        1
        for finding in findings
        if (finding.severity or "").lower() in {"critical", "high"} and finding.port in {22, 80, 443, 3389, 5432}
    )

    return {
        "internal_assets": internal_assets,
        "external_assets": external_assets,
        "web_assets": web_assets,
        "cloud_assets": cloud_assets,
        "mobile_assets": mobile_assets,
        "exposed_findings": exposed_findings,
        "internet_facing_targets": internet_facing_targets,
        "subdomain_candidates": subdomain_candidates,
    }


def summarize_attack_paths(db: Session) -> dict:
    scans = db.query(Scan).all()
    assets = db.query(Asset).all()
    findings = db.query(Finding).filter(Finding.status != "resolved").all()

    scan_by_id = {str(scan.id): scan for scan in scans}
    asset_by_target = {
        asset.hostname or asset.ip_address: asset
        for asset in assets
    }
    findings_by_target: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        scan = scan_by_id.get(str(finding.scan_id))
        if not scan:
            continue
        findings_by_target[scan.target].append(finding)

    paths: list[list[dict]] = []
    suggested_actions: set[str] = set()
    high_risk_paths = 0

    for target, target_findings in findings_by_target.items():
        prioritized = sorted(
            target_findings,
            key=lambda item: {"critical": 5, "high": 4, "medium": 3, "low": 2}.get((item.severity or "info").lower(), 1),
            reverse=True,
        )[:2]
        if not prioritized:
            continue
        asset = asset_by_target.get(target)
        chain = []
        for finding in prioritized:
            technique = "Initial Access"
            title = (finding.title or "").lower()
            if "credential" in title or "auth" in title:
                technique = "Valid Accounts"
                suggested_actions.add("Prioritize password rotation and MFA on authentication findings.")
            elif "tls" in title or "cipher" in title:
                technique = "Encrypted Channel Weakness"
                suggested_actions.add("Harden TLS profiles on exposed services and validate after re-scan.")
            elif finding.port in {80, 443, 8080}:
                technique = "Exploit Public-Facing Application"
                suggested_actions.add("Patch externally exposed web services first to reduce exploit paths.")
            elif finding.port in {22, 3389, 445}:
                technique = "Remote Services"
                suggested_actions.add("Restrict administrative ports to trusted networks only.")

            chain.append(
                {
                    "asset_name": asset.asset_name if asset else target,
                    "exposure": asset.exposure if asset else "external",
                    "finding_title": finding.title,
                    "severity": finding.severity or "info",
                    "technique": technique,
                    "target": target,
                }
            )
        if chain:
            paths.append(chain)
            if any((node["severity"] or "").lower() in {"critical", "high"} for node in chain):
                high_risk_paths += 1

    return {
        "total_paths": len(paths),
        "high_risk_paths": high_risk_paths,
        "suggested_actions": list(suggested_actions)[:5],
        "paths": paths[:6],
    }
