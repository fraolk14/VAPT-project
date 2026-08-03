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
    base = float(finding.cvss_score or 0)
    confidence_bonus = float(finding.confidence or 0) * 10
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
