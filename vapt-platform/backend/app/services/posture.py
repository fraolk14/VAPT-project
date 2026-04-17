from __future__ import annotations

from collections import Counter

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.platform import EndpointSoftwareInventory


RISKY_SOFTWARE_KEYWORDS = {
    "anydesk": "high",
    "teamviewer": "high",
    "wireshark": "medium",
    "nmap": "medium",
    "mimikatz": "critical",
    "unsignedtool": "high",
}

SHADOW_IT_KEYWORDS = {
    "notion",
    "dropbox",
    "trello",
    "asana",
    "discord",
    "shadow",
    "saas",
}


def build_shadow_it_summary(assets: list[Asset], findings: list[Finding] | None = None) -> dict:
    suspicious_services = []
    unknown_services = 0
    reviewed_services = 0
    for asset in assets:
        tags = [str(tag) for tag in (asset.tags or [])]
        tag_blob = " ".join(tags).lower()
        suspicious = any(keyword in tag_blob for keyword in SHADOW_IT_KEYWORDS) or (
            str(asset.exposure or "").lower() == "external" and not (asset.owner or "").strip()
        )
        if suspicious:
            unknown_services += 1
            suspicious_services.append(
                {
                    "label": asset.asset_name,
                    "value": asset.hostname or asset.ip_address,
                    "severity": "high" if "shadow" in tag_blob or "saas" in tag_blob else "medium",
                    "metadata": {
                        "tags": tags,
                        "business_unit": asset.business_unit,
                        "owner": asset.owner,
                    },
                }
            )
        else:
            reviewed_services += 1

    for finding in findings or []:
        metadata = finding.finding_metadata or {}
        target = metadata.get("url") or metadata.get("host") or ""
        text = f"{target} {finding.title} {finding.evidence or ''}".lower()
        suspicious = any(keyword in text for keyword in SHADOW_IT_KEYWORDS) or (
            finding.source in {"zap", "network-db", "openvas"} and target and not finding.assigned_to
        )
        if suspicious:
            unknown_services += 1
            suspicious_services.append(
                {
                    "label": finding.title,
                    "value": target or finding.source,
                    "severity": (finding.severity or "medium").lower(),
                    "metadata": {
                        "finding_id": str(finding.id),
                        "source": finding.source,
                        "reason": "Discovered from scan telemetry without an assigned owner.",
                    },
                }
            )

    return {
        "external_assets": sum(1 for asset in assets if str(asset.exposure or "").lower() == "external"),
        "cloud_assets": sum(
            1
            for asset in assets
            if str(asset.asset_type or "").lower() in {"cloud", "saas"} or bool(asset.cloud_provider)
        ),
        "unknown_services": unknown_services,
        "reviewed_services": reviewed_services,
        "suspicious_services": suspicious_services[:12],
        "connector_status": {
            "dns_logs": "heuristic",
            "traffic_analysis": "heuristic",
            "workspace_connectors": "planned",
        },
    }


def build_misconfiguration_summary(findings: list[Finding]) -> dict:
    categories = Counter()
    top_items = []
    for finding in findings:
        text = f"{finding.title} {finding.remediation or ''} {finding.evidence or ''}".lower()
        if "tls" in text or "transport-security" in text or "strict-transport-security" in text:
            categories["weak_tls"] += 1
        if finding.category == "network" or "port" in text or "service" in text:
            categories["exposed_services"] += 1
        if "auth" in text or "credential" in text or "password" in text or "session" in text:
            categories["auth_issues"] += 1
        if "cloud" in text or "bucket" in text or "s3" in text or "azure" in text or "gcp" in text:
            categories["cloud_findings"] += 1

        if finding.status == "open":
            top_items.append(
                {
                    "label": finding.title,
                    "value": finding.source,
                    "severity": (finding.severity or "info").lower(),
                    "metadata": {"cve_id": finding.cve_id, "compliance_map": finding.compliance_map or []},
                }
            )

    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    top_items.sort(key=lambda item: severity_order.get(item["severity"], 0), reverse=True)
    return {
        "weak_tls": categories["weak_tls"],
        "exposed_services": categories["exposed_services"],
        "auth_issues": categories["auth_issues"],
        "cloud_findings": categories["cloud_findings"],
        "categories": dict(categories),
        "top_items": top_items[:12],
    }


def classify_installed_apps(installed_apps: list[str], approved_baseline: list[str] | None = None) -> list[dict]:
    baseline = {item.strip().lower() for item in (approved_baseline or []) if item.strip()}
    detected_apps = []
    for app in [str(item).strip() for item in installed_apps if str(item).strip()]:
        normalized = app.lower()
        severity = None
        reason = None
        for keyword, keyword_severity in RISKY_SOFTWARE_KEYWORDS.items():
            if keyword in normalized:
                severity = keyword_severity
                reason = f"Matches risky software indicator '{keyword}'."
                break
        if baseline and normalized not in baseline:
            severity = severity or "medium"
            reason = reason or "Installed application is not in the approved baseline."
        if severity:
            detected_apps.append({"name": app, "severity": severity, "reason": reason or "Baseline drift detected."})
    return detected_apps


def build_software_summary(
    assets: list[Asset],
    inventories: list[EndpointSoftwareInventory] | None = None,
    findings: list[Finding] | None = None,
) -> dict:
    detected_apps = []
    unauthorized_apps = 0
    high_risk_apps = 0
    managed_endpoints = 0
    baseline_coverage = 0
    for asset in assets:
        asset_type = str(asset.asset_type or "").lower()
        if asset_type in {"endpoint", "workstation", "server"}:
            managed_endpoints += 1
            baseline_coverage += 1 if asset.owner else 0
            for tag in [str(tag) for tag in (asset.tags or [])]:
                normalized = tag.lower()
                for keyword, severity in RISKY_SOFTWARE_KEYWORDS.items():
                    if keyword in normalized:
                        unauthorized_apps += 1
                        if severity in {"high", "critical"}:
                            high_risk_apps += 1
                        detected_apps.append(
                            {
                                "label": tag,
                                "value": asset.asset_name,
                                "severity": severity,
                                "metadata": {"hostname": asset.hostname, "owner": asset.owner},
                            }
                        )

    for inventory in inventories or []:
        managed_endpoints += 1
        baseline_coverage += 1 if inventory.approved_baseline else 0
        for app in inventory.detected_apps or []:
            severity = app.get("severity", "medium")
            unauthorized_apps += 1
            if severity in {"high", "critical"}:
                high_risk_apps += 1
            detected_apps.append(
                {
                    "label": app.get("name") or "Unknown application",
                    "value": inventory.endpoint_name,
                    "severity": severity,
                    "metadata": {
                        "hostname": inventory.hostname,
                        "ip_address": inventory.ip_address,
                        "owner": inventory.reported_by,
                        "reason": app.get("reason"),
                        "source": inventory.source,
                    },
                }
            )

    for finding in findings or []:
        text = f"{finding.title} {finding.evidence or ''} {finding.remediation or ''} {finding.service or ''}".lower()
        for keyword, severity in RISKY_SOFTWARE_KEYWORDS.items():
            if keyword not in text:
                continue
            metadata = finding.finding_metadata or {}
            unauthorized_apps += 1
            if severity in {"high", "critical"}:
                high_risk_apps += 1
            detected_apps.append(
                {
                    "label": keyword.title(),
                    "value": metadata.get("host") or metadata.get("url") or finding.source,
                    "severity": severity,
                    "metadata": {
                        "hostname": metadata.get("host"),
                        "owner": finding.assigned_to,
                        "reason": f"Observed in scan evidence: {finding.title}",
                        "source": finding.source,
                        "finding_id": str(finding.id),
                    },
                }
            )

    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    detected_apps.sort(key=lambda item: severity_order.get(item["severity"], 0), reverse=True)
    return {
        "managed_endpoints": managed_endpoints,
        "unauthorized_apps": unauthorized_apps,
        "high_risk_apps": high_risk_apps,
        "baseline_coverage": baseline_coverage,
        "detected_apps": detected_apps[:12],
    }
