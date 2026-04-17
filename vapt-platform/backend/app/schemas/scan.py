from datetime import datetime
import ipaddress
import re
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.schemas.finding import FindingOut


FQDN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$"
)


def validate_network_target(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Target is required.")

    if "/" in normalized:
        try:
            network = ipaddress.ip_network(normalized, strict=False)
        except ValueError:
            network = None
        if network:
            if network.version != 4:
                raise ValueError("Network block scanning currently supports IPv4 CIDR ranges only.")
            if network.num_addresses > 256:
                raise ValueError("Network block scans are limited to /24 or smaller ranges for safety.")
            return str(network)

    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    if FQDN_PATTERN.fullmatch(normalized):
        return normalized.rstrip(".")

    raise ValueError("Target must be a valid IP address or fully qualified domain name.")


class ScanCreate(BaseModel):
    scan_name: str
    scan_type: str
    tool: str
    target: str
    profile: str = "standard"
    schedule: Optional[str] = None
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str, info):
        tool = (info.data.get("tool") or "").lower() if info.data else ""
        if tool == "openvas":
            return validate_network_target(value)
        return value.strip()


class NetworkScanRequest(BaseModel):
    target: str
    label: Optional[str] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return validate_network_target(value)


class WebScanRequest(BaseModel):
    target: str
    label: Optional[str] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return value.strip()


class ScanResponse(BaseModel):
    scan_name: str
    scan_type: str
    tool: str
    target: str
    profile: str = "standard"
    schedule: Optional[str] = None
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
        populate_by_name = True


class ScanDebugResponse(BaseModel):
    id: UUID
    scan_name: str
    tool: str
    status: str
    target: str
    progress: str
    error_message: Optional[str] = None
    engine_metadata: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    related_findings: list[FindingOut] = Field(default_factory=list)
    audit_trail: list[dict[str, Any]] = Field(default_factory=list)
