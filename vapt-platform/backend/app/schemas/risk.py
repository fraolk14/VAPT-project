from pydantic import BaseModel

class AssetRiskResponse(BaseModel):
    asset_id: str
    ip_address: str
    asset_type: str
    criticality: str | None
    risk_score: float
