from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    scan_name: str
    scan_type: str
    tool: str
    target: str
    profile: str = "standard"
    schedule: Optional[str] = None
    options: dict[str, Any] = Field(default_factory=dict)


class NetworkScanRequest(BaseModel):
    target: str
    label: Optional[str] = None


class ScanResponse(ScanCreate):
    id: UUID
    status: str
    progress: str
    engine_metadata: dict[str, Any]
    result_summary: dict[str, Any]
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True
