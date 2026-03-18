from collections import Counter

from app.models.finding import Finding


def compute_finding_priority(finding: Finding) -> float:
    base = finding.cvss_score or 0
    confidence_bonus = finding.confidence * 10
    exposure_bonus = 10 if finding.port in {22, 80, 443, 3389} else 0
    return round(base * 10 + confidence_bonus + exposure_bonus, 2)


def summarize_risk(findings: list[Finding]) -> dict:
    if not findings:
        return {"risk_score": 0.0, "severity_breakdown": {}, "open_findings": 0}

    breakdown = Counter((finding.severity or "info").lower() for finding in findings)
    total = sum(compute_finding_priority(finding) for finding in findings)
    open_findings = sum(1 for finding in findings if finding.status == "open")
    risk_score = round(total / max(len(findings), 1), 2)

    return {
        "risk_score": risk_score,
        "severity_breakdown": dict(breakdown),
        "open_findings": open_findings,
    }
