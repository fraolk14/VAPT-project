from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class TenantCreate(BaseModel):
    name: str
    slug: str
    settings: dict = Field(default_factory=dict)


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    settings: dict = Field(default_factory=dict)
    is_default: bool
    created_at: datetime

    class Config:
        from_attributes = True


class MonitoringRuleCreate(BaseModel):
    name: str
    event_source: str
    event_type: str
    target_match: str | None = None
    action: str = "queue_scan"
    tool: str = "openvas"
    metadata_json: dict = Field(default_factory=dict)


class MonitoringRuleResponse(BaseModel):
    id: UUID
    name: str
    event_source: str
    event_type: str
    target_match: str | None = None
    action: str
    tool: str
    enabled: bool
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class MonitoringEventCreate(BaseModel):
    source: str
    event_type: str
    target: str
    severity: str = "medium"
    payload: dict = Field(default_factory=dict)


class MonitoringEventResponse(BaseModel):
    id: UUID
    source: str
    event_type: str
    target: str
    severity: str
    status: str
    payload: dict = Field(default_factory=dict)
    triggered_scan_id: UUID | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityIncidentResponse(BaseModel):
    id: UUID
    title: str
    source: str
    severity: str
    status: str
    target: str
    summary: str | None = None
    related_finding_ids: list[str] = Field(default_factory=list)
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentStatusUpdate(BaseModel):
    status: str
    summary: str | None = None


class ComplianceTemplateResponse(BaseModel):
    id: UUID
    name: str
    framework: str
    controls: list[str] = Field(default_factory=list)
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceAssessmentResponse(BaseModel):
    id: UUID
    template_id: UUID
    name: str
    status: str
    score: str
    summary: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceSummaryResponse(BaseModel):
    templates: list[ComplianceTemplateResponse] = Field(default_factory=list)
    assessments: list[ComplianceAssessmentResponse] = Field(default_factory=list)
    mapped_findings: int = 0
    frameworks: dict[str, int] = Field(default_factory=dict)


class ComplianceAssessmentDownloadResponse(BaseModel):
    assessment: ComplianceAssessmentResponse
    framework: str | None = None
    controls: list[str] = Field(default_factory=list)
    generated_at: datetime


class AuditLogResponse(BaseModel):
    id: UUID
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    details: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True
