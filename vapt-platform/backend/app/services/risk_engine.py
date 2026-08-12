from collections import Counter

from app.models.finding import Finding

PORT_WEIGHTS = {
    3389: 9,
    445: 9,
    23: 9,
    22: 6,
    21: 6,
    80: 3,
    443: 3,
}

CRITICALITY_MULTIPLIER = {
    "critical": 1.5,
    "high": 1.3,
    "medium": 1.1,
    "low": 1.0,
    None: 1.0,
}


def compute_finding_priority(finding: Finding) -> float:
    severity = str(finding.severity or "info").lower()
    default_cvss = {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.5,
    }.get(severity, 1.0)
    base = float(finding.cvss_score if finding.cvss_score is not None and float(finding.cvss_score) > 0 else default_cvss)
    confidence_bonus = float(finding.confidence if finding.confidence is not None else 0.8) * 10
    exposure_bonus = 10 if (finding.port in {22, 80, 443, 3389, 8000, 8080}) else 5
    return round(base * 5 + confidence_bonus + exposure_bonus, 2)


def summarize_risk(findings: list[Finding]) -> dict:
    if not findings:
        return {"risk_score": 0.0, "severity_breakdown": {}, "open_findings": 0}

    breakdown = Counter((finding.severity or "info").lower() for finding in findings)
    
    # Filter for open / unresolved findings
    open_findings_list = [
        f for f in findings
        if str(f.status or "open").lower() in {"open", "new", "active", "unresolved"}
    ]
    open_count = len(open_findings_list)

    if not open_findings_list:
        return {"risk_score": 0.0, "severity_breakdown": dict(breakdown), "open_findings": 0}

    weight_map = {
        "critical": 35.0,
        "high": 20.0,
        "medium": 10.0,
        "low": 4.0,
        "info": 1.0,
    }
    raw_risk = sum(weight_map.get(str(f.severity or "info").lower(), 2.0) for f in open_findings_list)
    priority_sum = sum(compute_finding_priority(f) for f in open_findings_list)
    
    # Scale to standard 0-100 Global Risk Score
    calculated_risk = round(min(100.0, max(0.0, (raw_risk * 1.2) + (priority_sum / max(open_count, 1)))), 2)

    return {
        "risk_score": calculated_risk,
        "severity_breakdown": dict(breakdown),
        "open_findings": open_count,
    }


def calculate_risk(cvss_score: float | int | None, *, port: int | None = None, criticality: str | None = None) -> tuple[float, str]:
    normalized = float(cvss_score or 0)
    risk_score = normalized * 10
    if port is not None:
        risk_score += PORT_WEIGHTS.get(port, 1) * 2
    multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.0)
    risk_score *= multiplier
    risk_score = round(risk_score, 2)
    if risk_score >= 80:
        return risk_score, "critical"
    if risk_score >= 50:
        return risk_score, "high"
    if risk_score >= 25:
        return risk_score, "medium"
    if risk_score > 0:
        return risk_score, "low"
    return risk_score, "info"
