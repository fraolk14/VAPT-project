from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    asset_name: str
    ip_address: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    asset_type: str
    environment: Optional[str] = "prod"
    criticality: Optional[str] = "medium"
    owner: Optional[str] = None
    exposure: Optional[str] = "internal"
    tags: list[str] = Field(default_factory=list)
    cloud_provider: Optional[str] = None
    business_unit: Optional[str] = None


class AssetResponse(AssetCreate):
    id: UUID
    risk_score: float

    class Config:
        from_attributes = True
