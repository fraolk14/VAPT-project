from datetime import datetime
import ipaddress
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class AssetCreate(BaseModel):
    asset_name: str
    ip_address: Optional[str] = None
    url: Optional[str] = None
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

    @model_validator(mode="after")
    def validate_address(self):
        ip_value = (self.ip_address or "").strip() or None
        url_value = (self.url or "").strip() or None
        parsed_url = None
        if not ip_value and not url_value:
            raise ValueError("Provide an IP address, hostname, or URL for the asset.")
        if url_value:
            parsed_url = urlparse(url_value)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                raise ValueError("URL assets must start with http:// or https://")
            self.url = url_value
            if not self.hostname:
                self.hostname = parsed_url.hostname
        if ip_value:
            try:
                ipaddress.ip_address(ip_value)
            except ValueError:
                self.hostname = ip_value
            self.ip_address = ip_value
        elif url_value:
            self.ip_address = self.hostname or (parsed_url.hostname if parsed_url else None)
        return self


class AssetResponse(AssetCreate):
    id: UUID
    risk_score: float
    created_at: datetime

    class Config:
        from_attributes = True
