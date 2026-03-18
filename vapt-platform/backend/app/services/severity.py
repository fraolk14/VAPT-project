def port_severity(port: int) -> str:
    if port in [23, 445, 3389]:
        return "high"
    if port in [21, 22]:
        return "medium"
    if port in [80, 443]:
        return "low"
    return "info"
