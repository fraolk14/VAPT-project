from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class PluginCreate(BaseModel):
    name: str
    plugin_type: str
    version: str = "1.0.0"
    entrypoint: str
    capabilities: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)


class PluginResponse(BaseModel):
    id: UUID
    name: str
    plugin_type: str
    version: str
    entrypoint: str
    enabled: bool
    capabilities: list[str] = Field(default_factory=list)
    config: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    name: str
    role_scope: str = "analyst"


class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    role_scope: str
    enabled: bool
    last_used_at: datetime | None = None
    created_at: datetime

    class Config:
        from_attributes = True


class ApiKeyCreateResponse(ApiKeyResponse):
    secret: str


class DevSecOpsHookCreate(BaseModel):
    name: str
    provider: str
    project_name: str
    target_url: str
    metadata_json: dict = Field(default_factory=dict)


class DevSecOpsHookResponse(BaseModel):
    id: UUID
    name: str
    provider: str
    project_name: str
    target_url: str
    enabled: bool
    secret_hint: str
    metadata_json: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class DevSecOpsHookCreateResponse(DevSecOpsHookResponse):
    secret: str


class DevSecOpsEventResponse(BaseModel):
    id: UUID
    hook_id: UUID | None = None
    event_type: str
    provider: str
    status: str
    summary: str | None = None
    payload: dict = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class AttackSurfaceSummary(BaseModel):
    internal_assets: int
    external_assets: int
    web_assets: int
    cloud_assets: int
    mobile_assets: int
    exposed_findings: int
    internet_facing_targets: list[str] = Field(default_factory=list)
    subdomain_candidates: list[str] = Field(default_factory=list)


class AttackPathNode(BaseModel):
    asset_name: str
    exposure: str
    finding_title: str
    severity: str
    technique: str
    target: str


class AttackPathSummary(BaseModel):
    total_paths: int
    high_risk_paths: int
    suggested_actions: list[str] = Field(default_factory=list)
    paths: list[list[AttackPathNode]] = Field(default_factory=list)
