from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.dashboard import (
    DashboardAttackActivity,
    DashboardMetric,
    DashboardOwaspSummary,
    DashboardSummary,
    DashboardTargetSummary,
)
from app.services.risk_engine import summarize_risk

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]
OWASP_CATEGORY_MAP = [
    ("A01:2021 Broken Access Control", ["access control", "idor", "forced browsing", "authz"]),
    ("A02:2021 Cryptographic Failures", ["tls", "ssl", "cryptographic", "encryption", "cookie without secure flag"]),
    ("A03:2021 Injection", ["sql injection", "xss", "cross site scripting", "command injection", "ldap injection", "path traversal"]),
    ("A04:2021 Insecure Design", ["business logic", "insecure design"]),
    ("A05:2021 Security Misconfiguration", ["misconfiguration", "header not set", "directory listing", "default credentials", "csp", "clickjacking"]),
    ("A06:2021 Vulnerable and Outdated Components", ["outdated", "cpe inventory", "vulnerable package", "unsupported"]),
    ("A07:2021 Identification and Authentication Failures", ["authentication", "password", "session", "anti-clickjacking", "csrf", "mfa"]),
    ("A08:2021 Software and Data Integrity Failures", ["integrity", "unsigned", "deserialization", "supply chain"]),
    ("A09:2021 Security Logging and Monitoring Failures", ["logging", "monitoring", "audit"]),
    ("A10:2021 Server-Side Request Forgery", ["ssrf", "server side request forgery"]),
]


def _extract_owasp_category(finding: Finding) -> str | None:
    compliance_map = finding.compliance_map or []
    for item in compliance_map:
        if isinstance(item, str) and item.startswith("A") and ":2021" in item:
            return item

    haystack = " ".join(
        filter(
            None,
            [
                finding.title.lower(),
                ((finding.finding_metadata or {}).get("attack") or "").lower(),
                ((finding.finding_metadata or {}).get("reference") or "").lower(),
            ],
        )
    )
    for category, terms in OWASP_CATEGORY_MAP:
        if any(term in haystack for term in terms):
            return category
    if finding.source == "zap" and "OWASP Top 10" in compliance_map:
        return "A05:2021 Security Misconfiguration"
    return None


def _extract_attack_name(finding: Finding) -> str | None:
    metadata = finding.finding_metadata or {}
    raw_attack = metadata.get("attack") or metadata.get("param") or finding.title
    if not raw_attack:
        return None
    attack = str(raw_attack).strip()
    if finding.source == "openvas" and attack.lower() == finding.title.lower():
        if "enumeration" in attack.lower():
            return "Service Enumeration"
        if "inventory" in attack.lower():
            return "Asset Exposure"
    return attack[:120]


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    risk = summarize_risk(findings)
    coverage = Counter(scan.tool for scan in scans)
    findings_by_scan_id: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_scan_id.setdefault(str(finding.scan_id), []).append(finding)

    target_worst_severity: dict[str, str] = {}
    target_worst_severity_by_tool: dict[str, dict[str, str]] = {}
    for scan in scans:
        if scan.status != "completed":
            continue

        scan_findings = findings_by_scan_id.get(str(scan.id), [])
        worst = "info"
        for finding in scan_findings:
            severity = (finding.severity or "info").lower()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(worst, 0):
                worst = severity

        existing = target_worst_severity.get(scan.target)
        if existing is None or SEVERITY_ORDER.get(worst, 0) > SEVERITY_ORDER.get(existing, 0):
            target_worst_severity[scan.target] = worst

        tool_targets = target_worst_severity_by_tool.setdefault(scan.tool, {})
        existing_tool_severity = tool_targets.get(scan.target)
        if existing_tool_severity is None or SEVERITY_ORDER.get(worst, 0) > SEVERITY_ORDER.get(existing_tool_severity, 0):
            tool_targets[scan.target] = worst

    target_severity_breakdown = {
        severity: sum(1 for value in target_worst_severity.values() if value == severity)
        for severity in SEVERITY_LEVELS
    }
    target_severity_by_tool = {
        tool: {
            severity: sum(1 for value in tool_targets.values() if value == severity)
            for severity in SEVERITY_LEVELS
        }
        for tool, tool_targets in target_worst_severity_by_tool.items()
    }
    owasp_counts = Counter()
    attack_activity: dict[tuple[str, str], dict[str, str | int]] = {}
    for finding in findings:
        owasp_category = _extract_owasp_category(finding)
        if owasp_category:
            owasp_counts[owasp_category] += 1

        attack_name = _extract_attack_name(finding)
        if not attack_name:
            continue
        key = (attack_name, finding.source)
        existing_attack = attack_activity.get(key)
        severity = (finding.severity or "info").lower()
        if existing_attack is None:
            attack_activity[key] = {
                "attack": attack_name,
                "count": 1,
                "severity": severity,
                "source": finding.source,
            }
            continue
        existing_attack["count"] += 1
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(str(existing_attack["severity"]), 0):
            existing_attack["severity"] = severity

    scanned_targets = []
    for scan in scans:
        if scan.status != "completed":
            continue

        scan_findings = findings_by_scan_id.get(str(scan.id), [])
        worst = "info"
        for finding in scan_findings:
            severity = (finding.severity or "info").lower()
            if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(worst, 0):
                worst = severity

        scanned_targets.append(
            DashboardTargetSummary(
                target=scan.target,
                tool=scan.tool,
                severity=worst,
                finding_count=len(scan_findings),
            )
        )

    metrics = [
        DashboardMetric(label="Assets Monitored", value="2", trend="+12%"),
        DashboardMetric(
            label="Active Campaigns",
            value=str(sum(1 for scan in scans if scan.status == "running")),
            trend="+2",
        ),
        DashboardMetric(label="Open Findings", value=str(risk["open_findings"]), trend="-8%"),
        DashboardMetric(label="Risk Score", value=str(risk["risk_score"]), trend="-4.3%"),
    ]

    return DashboardSummary(
        metrics=metrics,
        scanned_targets=scanned_targets,
        tool_coverage=dict(coverage),
        severity_breakdown=risk["severity_breakdown"],
        target_severity_breakdown=target_severity_breakdown,
        target_severity_by_tool=target_severity_by_tool,
        owasp_top10=[
            DashboardOwaspSummary(category=category, count=count)
            for category, count in owasp_counts.most_common(6)
        ],
        attack_activity=[
            DashboardAttackActivity(
                attack=str(item["attack"]),
                count=int(item["count"]),
                severity=str(item["severity"]),
                source=str(item["source"]),
            )
            for item in sorted(
                attack_activity.values(),
                key=lambda value: (
                    SEVERITY_ORDER.get(str(value["severity"]), 0),
                    int(value["count"]),
                ),
                reverse=True,
            )[:6]
        ],
        open_findings=risk["open_findings"],
        active_scans=sum(1 for scan in scans if scan.status == "running"),
        risk_score=risk["risk_score"],
    )
