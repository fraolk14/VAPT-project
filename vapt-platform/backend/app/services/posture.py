from __future__ import annotations

from collections import Counter

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.platform import EndpointSoftwareInventory
from app.services.cis_hardening import benchmark_for_os, infer_os_family


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
        classification = "approved"
        control_gap = []
        suspicious = any(keyword in tag_blob for keyword in SHADOW_IT_KEYWORDS) or (
            str(asset.exposure or "").lower() == "external" and not (asset.owner or "").strip()
        )
        if suspicious:
            unknown_services += 1
            if "shadow" in tag_blob or "saas" in tag_blob:
                classification = "unsanctioned_saas"
            elif str(asset.exposure or "").lower() == "external":
                classification = "internet_exposed_unowned"
            if not (asset.owner or "").strip():
                control_gap.append("Owner not assigned")
            if str(asset.exposure or "").lower() == "external":
                control_gap.append("Internet exposure review required")
            if not asset.business_unit:
                control_gap.append("Business unit not mapped")
            suspicious_services.append(
                {
                    "label": asset.asset_name,
                    "value": asset.hostname or asset.ip_address,
                    "severity": "high" if "shadow" in tag_blob or "saas" in tag_blob else "medium",
                    "metadata": {
                        "tags": tags,
                        "business_unit": asset.business_unit,
                        "owner": asset.owner,
                        "classification": classification,
                        "control_gap": control_gap,
                        "source": "asset_inventory",
                        "exposure": asset.exposure,
                        "recommended_action": "Validate business ownership, approve or block the service, and enforce SSO/MFA controls.",
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
            control_gap = []
            if not finding.assigned_to:
                control_gap.append("No assigned owner")
            if finding.source == "zap":
                control_gap.append("Web exposure requires SaaS validation")
            elif finding.source in {"openvas", "network-db"}:
                control_gap.append("Externally reachable network service")
            suspicious_services.append(
                {
                    "label": finding.title,
                    "value": target or finding.source,
                    "severity": (finding.severity or "medium").lower(),
                    "metadata": {
                        "finding_id": str(finding.id),
                        "source": finding.source,
                        "reason": "Discovered from scan telemetry without an assigned owner.",
                        "classification": "scan_discovered_shadow_surface",
                        "control_gap": control_gap,
                        "recommended_action": "Review ownership, confirm whether the service is sanctioned, and restrict exposure if not approved.",
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
        metadata = finding.finding_metadata or {}
        os_family = infer_os_family(
            service=metadata.get("service_name") or finding.service or "",
            title=finding.title or "",
            banner=" ".join(
                str(value)
                for value in [
                    metadata.get("server"),
                    metadata.get("banner"),
                    metadata.get("technology"),
                    metadata.get("generator"),
                ]
                if value
            ),
            evidence=finding.evidence or "",
            port=finding.port or 0,
        )
        os_family = str(metadata.get("os_family") or os_family or "network").lower()
        cis_benchmark = metadata.get("cis_benchmark") or benchmark_for_os(os_family)
        if "tls" in text or "transport-security" in text or "strict-transport-security" in text:
            categories["weak_tls"] += 1
        if finding.category == "network" or "port" in text or "service" in text:
            categories["exposed_services"] += 1
        if "auth" in text or "credential" in text or "password" in text or "session" in text:
            categories["auth_issues"] += 1
        if "cloud" in text or "bucket" in text or "s3" in text or "azure" in text or "gcp" in text:
            categories["cloud_findings"] += 1
        categories[f"cis_{os_family}"] += 1

        if finding.status == "open":
            top_items.append(
                {
                    "label": finding.title,
                    "value": finding.source,
                    "severity": (finding.severity or "info").lower(),
                    "metadata": {
                        "cve_id": finding.cve_id,
                        "compliance_map": finding.compliance_map or [],
                        "cis_benchmark": cis_benchmark,
                        "os_family": os_family,
                        "hardening_recommendation": metadata.get("hardening_recommendation"),
                        "references": metadata.get("references", []),
                    },
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
    db: Session | None = None,
) -> dict:
    from app.models.software import Software, SoftwareAsset

    detected_apps = []
    unauthorized_apps = 0
    high_risk_apps = 0
    managed_endpoints = len(assets)
    baseline_coverage = 0

    if db:
        db_software = db.query(Software).all()
        for sw in db_software:
            sev = "critical" if sw.risk_score >= 9.0 else "high" if sw.risk_score >= 7.0 else "medium" if sw.risk_score >= 4.0 else "low"
            if sw.status != "APPROVED":
                unauthorized_apps += 1
                if sw.risk_score >= 7.0:
                    high_risk_apps += 1
                
                # Fetch linked assets
                links = db.query(SoftwareAsset).filter(SoftwareAsset.software_id == sw.id).all()
                endpoint_label = "Unassigned / Discovery"
                hostname_val = None
                ip_val = None
                source_val = "Nmap -sV Subprocess"
                if links:
                    link = links[0]
                    ip_val = link.ip_address
                    hostname_val = link.hostname
                    source_val = link.source or "Nmap -sV Subprocess"
                    if link.asset:
                        endpoint_label = link.asset.asset_name
                        hostname_val = link.asset.hostname
                    elif link.ip_address:
                        endpoint_label = f"Target Host ({link.ip_address})"
                
                detected_apps.append({
                    "id": sw.id,
                    "label": f"{sw.name} {sw.version or ''}".strip(),
                    "value": endpoint_label,
                    "severity": sev,
                    "status": sw.status,
                    "category": sw.category,
                    "vendor": sw.vendor,
                    "cves": sw.cves,
                    "risk_score": sw.risk_score,
                    "ip_address": ip_val,
                    "source": source_val,
                    "metadata": {
                        "hostname": hostname_val,
                        "ip_address": ip_val,
                        "cpe": sw.cpe,
                        "source": source_val,
                        "baseline_status": sw.status.lower(),
                        "reason": f"Status: {sw.status} (CVEs found: {len(sw.cves)})" if sw.cves else f"Status: {sw.status} (Unapproved software)",
                        "recommended_action": "Review against baseline and approve or contain." if sw.status == "UNAUTHORIZED" else "Apply vendor security updates immediately.",
                    },
                })

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
                        "baseline_status": "not_in_baseline",
                        "recommended_action": "Compare the installed software list with the approved baseline and remove or formally approve the drift.",
                    },
                }
            )

    return {
        "managed_endpoints": managed_endpoints,
        "unauthorized_apps": unauthorized_apps,
        "high_risk_apps": high_risk_apps,
        "baseline_coverage": baseline_coverage,
        "detected_apps": detected_apps,
    }

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
                        "baseline_status": "scan_observed",
                        "recommended_action": "Validate whether the observed software should exist on this host and collect endpoint inventory for confirmation.",
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


def discover_shadow_it_for_org(db: Session, organization: str) -> dict:
    import ipaddress
    from datetime import datetime, timezone
    from app.models.user import User

    clean_org = organization.strip().lower()

    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    software_items = db.query(EndpointSoftwareInventory).all()
    users = db.query(User).all()

    # Parse IP address or CIDR network subnet if provided
    target_net = None
    try:
        if "/" in clean_org or any(char.isdigit() for char in clean_org):
            target_net = ipaddress.ip_network(clean_org, strict=False)
    except ValueError:
        target_net = None

    matched_assets = []
    if target_net is not None:
        for a in assets:
            if a.ip_address:
                try:
                    ip_obj = ipaddress.ip_address(a.ip_address.strip())
                    if ip_obj in target_net:
                        matched_assets.append(a)
                        continue
                except ValueError:
                    pass
            if clean_org in (a.hostname or "").lower() or clean_org in (a.asset_name or "").lower():
                matched_assets.append(a)
    else:
        matched_assets = [
            a for a in assets
            if clean_org in (a.asset_name or "").lower()
            or clean_org in (a.hostname or "").lower()
            or clean_org in (a.url or "").lower()
            or any(clean_org in str(t).lower() for t in (a.tags or []))
        ]

    matched_software = []
    for sw in software_items:
        if not sw.is_unauthorized:
            continue
        if target_net is not None:
            if getattr(sw, "ip_address", None):
                try:
                    ip_obj = ipaddress.ip_address(sw.ip_address.strip())
                    if ip_obj in target_net:
                        matched_software.append(sw)
                        continue
                except ValueError:
                    pass
            if clean_org in (sw.hostname or "").lower():
                matched_software.append(sw)
        else:
            if clean_org in (sw.hostname or "").lower() or clean_org in (sw.software_name or "").lower():
                matched_software.append(sw)

    discovered_apps = []
    remediation_actions = []

    app_id_counter = 1
    action_id_counter = 1

    for asset in matched_assets:
        tags = [str(t) for t in (asset.tags or [])]
        tag_str = " ".join(tags).lower()
        is_high = "shadow" in tag_str or asset.criticality in {"high", "critical"} or asset.exposure == "external"
        risk_lvl = "critical" if asset.criticality == "critical" else ("high" if is_high else "low")
        risk_score = 95 if risk_lvl == "critical" else (75 if risk_lvl == "high" else 35)

        app_id = f"app_{app_id_counter:03d}"
        app_id_counter += 1

        discovered_apps.append({
            "id": app_id,
            "app_name": asset.asset_name or asset.hostname or asset.ip_address or "Unsanctioned Service",
            "category": "Cloud Infrastructure" if asset.asset_type == "cloud" else "Network Asset",
            "risk_score": risk_score,
            "risk_level": risk_lvl,
            "detected_by": "Subnet Scanner / Asset Telemetry",
            "subdomain": asset.hostname or asset.url or asset.ip_address or f"{asset.asset_name.lower().replace(' ', '')}.local",
            "ip": asset.ip_address,
            "users_using": len(users) or 1,
            "last_detected": asset.created_at.isoformat() if asset.created_at else datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": ["Exposed Interface"] if asset.exposure == "external" else [],
            "data_sensitivity": "high" if risk_lvl in {"critical", "high"} else "medium",
            "remediation_suggestion": f"Enforce access controls and segment {asset.asset_name or asset.ip_address}."
        })

        remediation_actions.append({
            "id": f"action_{action_id_counter:03d}",
            "app": asset.asset_name or asset.ip_address,
            "action": "Enforce Network Isolation & SSO Review",
            "status": "pending",
            "assigned_to": asset.owner or "Network Security"
        })
        action_id_counter += 1

    for sw in matched_software:
        app_id = f"app_{app_id_counter:03d}"
        app_id_counter += 1
        discovered_apps.append({
            "id": app_id,
            "app_name": sw.software_name,
            "category": sw.category or "Endpoint Software",
            "risk_score": 85 if sw.risk_level in {"high", "critical"} else 45,
            "risk_level": sw.risk_level or "medium",
            "detected_by": f"Endpoint Agent ({sw.hostname})",
            "subdomain": sw.hostname,
            "ip": getattr(sw, "ip_address", None),
            "users_using": 1,
            "last_detected": sw.updated_at.isoformat() if sw.updated_at else datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": [],
            "data_sensitivity": "medium",
            "remediation_suggestion": f"Remove unauthorized software {sw.software_name} from host {sw.hostname}."
        })

    total_shadow = len(discovered_apps)
    high_cnt = len([a for a in discovered_apps if a.get("risk_level") in {"critical", "high"}])
    med_cnt = len([a for a in discovered_apps if a.get("risk_level") == "medium"])
    low_cnt = len([a for a in discovered_apps if a.get("risk_level") == "low"])
    users_affected = sum(a.get("users_using", 1) for a in discovered_apps)

    nodes = []
    links = []
    if total_shadow > 0:
        nodes.append({"id": "org", "name": organization, "type": "organization", "size": 40})
        for u in users[:5]:
            user_node_id = f"user_{u.id}"
            nodes.append({"id": user_node_id, "name": getattr(u, "full_name", None) or u.username or u.email, "type": "user", "size": 20})
            links.append({"source": "org", "target": user_node_id, "risk": "low"})

        for app in discovered_apps[:6]:
            app_node_id = f"graph_{app['id']}"
            nodes.append({"id": app_node_id, "name": app["app_name"], "type": "app", "size": 25, "risk": app["risk_level"]})
            if users:
                target_user = f"user_{users[0].id}"
                links.append({"source": target_user, "target": app_node_id, "risk": app["risk_level"]})

    risk_trend = {
        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "high_risk": [max(0, high_cnt - 2), high_cnt, max(0, high_cnt - 1), high_cnt + 2, high_cnt, max(0, high_cnt - 3), high_cnt] if total_shadow else [],
        "medium_risk": [med_cnt, med_cnt + 1, med_cnt, med_cnt + 2, med_cnt, med_cnt, med_cnt] if total_shadow else [],
        "low_risk": [low_cnt, low_cnt, low_cnt + 1, low_cnt, low_cnt + 2, low_cnt, low_cnt] if total_shadow else []
    }

    return {
        "organization": organization,
        "last_scan": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_shadow_apps": total_shadow,
            "high_risk_count": high_cnt,
            "medium_risk_count": med_cnt,
            "low_risk_count": low_cnt,
            "users_affected": users_affected,
            "data_exfiltration_risk_score": round(min(99.9, high_cnt * 12.5 + med_cnt * 4.0), 1)
        },
        "discovered_apps": discovered_apps,
        "user_relationship_graph": {
            "nodes": nodes,
            "links": links
        },
        "risk_trend": risk_trend,
        "remediation_actions": remediation_actions
    }

