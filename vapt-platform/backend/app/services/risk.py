from app.models.finding import Finding
from app.models.asset import Asset

PORT_WEIGHTS = {
    3389: 9,  # RDP
    445: 9,   # SMB
    23: 9,    # Telnet
    22: 6,    # SSH
    21: 6,    # FTP
    80: 3,    # HTTP
    443: 3,   # HTTPS
}

CRITICALITY_MULTIPLIER = {
    "critical": 1.5,
    "high": 1.3,
    "medium": 1.1,
    "low": 1.0,
    None: 1.0
}

def calculate_asset_risk(asset: Asset, findings: list[Finding]) -> float:
    base_score = 0

    for f in findings:
        if f.status != "open":
            continue
        base_score += PORT_WEIGHTS.get(f.port, 1)

    multiplier = CRITICALITY_MULTIPLIER.get(asset.criticality, 1.0)
    return round(base_score * multiplier, 2)
