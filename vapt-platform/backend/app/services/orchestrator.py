from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.finding import AuditLog, Finding
from app.models.scan import Scan
from app.services.integrations import MobSFClient, OpenVASClient, ZAPClient


def _mock_results(scan: Scan) -> list[dict[str, Any]]:
    if scan.tool == "openvas":
        return OpenVASClient().normalize_results(
            [
                {
                    "name": "TLS weak ciphers",
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "cvss": 7.5,
                    "host": scan.target,
                    "solution": "Disable legacy TLS and weak cipher suites.",
                }
            ]
        )
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


def run_scan(db: Session, scan: Scan) -> Scan:
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    scan.progress = "35"
    db.commit()

    normalized_findings = _mock_results(scan)
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

    scan.status = "completed"
    scan.progress = "100"
    scan.finished_at = datetime.now(timezone.utc)
    scan.result_summary = {
        "finding_count": len(normalized_findings),
        "sources": [scan.tool],
        "target": scan.target,
    }
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
