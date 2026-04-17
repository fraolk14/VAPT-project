from uuid import UUID

from pydantic import BaseModel, Field


class PostureListItem(BaseModel):
    label: str
    value: str
    severity: str = "info"
    metadata: dict = Field(default_factory=dict)


class ShadowITSummary(BaseModel):
    external_assets: int
    cloud_assets: int
    unknown_services: int
    reviewed_services: int
    suspicious_services: list[PostureListItem] = Field(default_factory=list)
    connector_status: dict[str, str] = Field(default_factory=dict)


class MisconfigurationSummary(BaseModel):
    weak_tls: int
    exposed_services: int
    auth_issues: int
    cloud_findings: int
    categories: dict[str, int] = Field(default_factory=dict)
    top_items: list[PostureListItem] = Field(default_factory=list)


class UnauthorizedSoftwareSummary(BaseModel):
    managed_endpoints: int
    unauthorized_apps: int
    high_risk_apps: int
    baseline_coverage: int
    detected_apps: list[PostureListItem] = Field(default_factory=list)


class EndpointSoftwareIngest(BaseModel):
    endpoint_name: str
    hostname: str | None = None
    ip_address: str | None = None
    os_name: str | None = None
    source: str = "agent"
    installed_apps: list[str] = Field(default_factory=list)
    approved_baseline: list[str] = Field(default_factory=list)


class EndpointSoftwareInventoryResponse(BaseModel):
    id: UUID
    endpoint_name: str
    hostname: str | None = None
    ip_address: str | None = None
    os_name: str | None = None
    source: str
    reported_by: str | None = None
    installed_apps: list[str] = Field(default_factory=list)
    approved_baseline: list[str] = Field(default_factory=list)
    detected_apps: list[dict] = Field(default_factory=list)
    status: str

    class Config:
        from_attributes = True
