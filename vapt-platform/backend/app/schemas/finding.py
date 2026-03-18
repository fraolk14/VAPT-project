from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    id: UUID
    scan_id: UUID
    asset_id: Optional[UUID] = None
    vulnerability_id: Optional[UUID] = None
    title: str
    category: str
    source: str
    status: str
    port: int
    protocol: str
    service: Optional[str]
    state: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    severity: Optional[str]
    confidence: float
    evidence: Optional[str]
    remediation: Optional[str]
    compliance_map: list[str] = Field(default_factory=list)
    finding_metadata: dict = Field(default_factory=dict)
    detected_at: datetime

    class Config:
        from_attributes = True
