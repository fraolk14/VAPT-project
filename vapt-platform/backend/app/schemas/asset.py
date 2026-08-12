from datetime import datetime
import ipaddress
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    url: Optional[str] = None
    os_type: Optional[str] = None  # e.g. "Ubuntu 22.04", "Windows Server 2019"
    os: Optional[str] = None

    owner: Optional[str] = None  # Email address
    environment: str = "Production"  # "Production", "Staging", "Development", "Test"
    criticality: str = "Medium"  # "Critical", "High", "Medium", "Low"
    risk_level: str = "Medium"  # "High", "Medium", "Low"

    classification: str = "Internal"  # "Internal" or "External"
    exposure: Optional[str] = "internal"
    asset_type: str = "OS"  # "OS", "Network", "Website", "Endpoint"
    asset_name: Optional[str] = None
    
    tags: list[str] = Field(default_factory=list)
    cloud_provider: Optional[str] = None
    business_unit: Optional[str] = None
    is_active: bool = True

    @model_validator(mode="after")
    def validate_address(self):
        ip_value = (self.ip_address or "").strip()
        url_value = (self.url or "").strip() or None
        host_value = (self.hostname or "").strip()

        if not ip_value and host_value:
            self.ip_address = host_value
        elif not ip_value and not url_value and not host_value:
            self.ip_address = "127.0.0.1"

        if not host_value:
            self.hostname = self.ip_address or "unnamed-host"

        if not self.os_type and self.os:
            self.os_type = self.os
        elif not self.os and self.os_type:
            self.os = self.os_type

        if not self.asset_name:
            self.asset_name = self.hostname or self.ip_address or "Asset"

        if self.classification:
            self.exposure = self.classification.lower()

        return self


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    url: Optional[str] = None
    os_type: Optional[str] = None
    os: Optional[str] = None
    owner: Optional[str] = None
    environment: Optional[str] = None
    criticality: Optional[str] = None
    risk_level: Optional[str] = None
    classification: Optional[str] = None
    asset_type: Optional[str] = None
    is_active: Optional[bool] = None


class MisconfigurationBrief(BaseModel):
    id: int
    issue: str
    severity: str
    cve: Optional[str] = None
    detected_by: str
    remediation: Optional[str] = None
    status: str
    discovered_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AssetResponse(BaseModel):
    id: UUID
    hostname: str
    ip_address: str
    url: Optional[str] = None
    os_type: Optional[str] = None
    os: Optional[str] = None
    owner: Optional[str] = None
    environment: str
    criticality: str
    risk_level: str
    classification: str
    exposure: Optional[str] = None
    asset_type: str
    asset_name: Optional[str] = None
    is_active: bool
    risk_score: float
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_scan_id: Optional[int] = None
    misconfigurations_count: int = 0
    misconfigurations: list[MisconfigurationBrief] = Field(default_factory=list)

    class Config:
        from_attributes = True
