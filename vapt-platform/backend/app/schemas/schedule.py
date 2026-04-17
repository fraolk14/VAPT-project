from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.scan import validate_network_target


class ScheduledScanCreate(BaseModel):
    job_name: str
    scan_type: str
    tool: str
    target: str
    profile: str = "standard"
    cadence_minutes: int = 60
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str, info):
        tool = (info.data.get("tool") or "").lower() if info.data else ""
        if tool == "openvas":
            return validate_network_target(value)
        return value.strip()


class ScheduledScanResponse(BaseModel):
    id: UUID
    job_name: str
    scan_type: str
    tool: str
    target: str
    profile: str
    cadence_minutes: str
    options: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None

    class Config:
        from_attributes = True
