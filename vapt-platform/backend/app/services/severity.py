def port_exposure_severity(port: int) -> str:
    if port in [23, 445, 3389]:
        return "high"
    if port in [21, 22]:
        return "medium"
    if port in [80, 443]:
        return "low"
    return "info"


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"