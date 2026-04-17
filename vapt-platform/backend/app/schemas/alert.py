from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class AlertRuleCreate(BaseModel):
    name: str
    channel: str
    destination: str
    min_severity: str = "high"
    scan_tool: str | None = None
    metadata_json: dict = Field(default_factory=dict)


class AlertRuleResponse(BaseModel):
    id: UUID
    name: str
    channel: str
    destination: str
    min_severity: str
    scan_tool: str | None = None
    enabled: bool
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class AlertEventResponse(BaseModel):
    id: UUID
    rule_name: str
    channel: str
    destination: str
    finding_id: str | None = None
    status: str
    payload: dict = Field(default_factory=dict)
    response_message: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class AlertRuleTestResponse(BaseModel):
    rule: AlertRuleResponse
    event: AlertEventResponse
