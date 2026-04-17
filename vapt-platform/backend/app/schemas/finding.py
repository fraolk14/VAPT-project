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
    assigned_to: Optional[str] = None
    team_name: Optional[str] = None
    sla_due_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    verification_state: str = "pending"
    compliance_map: list[str] = Field(default_factory=list)
    finding_metadata: dict = Field(default_factory=dict)
    duplicate_count: int = 1
    group_key: str = ""
    display_id: Optional[str] = None
    detected_at: datetime
    scan_finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    mark_false_positive: bool = False
    assigned_to: Optional[str] = None
    team_name: Optional[str] = None
    sla_due_at: Optional[datetime] = None
    verification_state: Optional[str] = None


class FalsePositiveRuleOut(BaseModel):
    id: UUID
    title_pattern: str
    cve_id: Optional[str] = None
    source: Optional[str] = None
    reason: Optional[str] = None
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True
