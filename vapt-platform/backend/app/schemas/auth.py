from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"
    group_name: str | None = None
    mfa_delivery_method: str = "totp"

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        normalized = value.strip()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Email must contain a valid local and domain part.")
        return normalized


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str | None = None
    role: str | None = None
    group_name: str | None = None
    mfa_delivery_method: str | None = None
    mfa_enabled: bool | None = None
    is_active: bool | None = None

    @field_validator("email")
    @classmethod
    def validate_optional_email(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Email must contain a valid local and domain part.")
        return normalized


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int = 0
    requires_mfa: bool = False
    mfa_ticket: str | None = None
    session_id: str | None = None
    device_name: str | None = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    tenant_id: str
    group_name: str | None = None
    role: str
    auth_source: str
    mfa_enabled: bool
    mfa_delivery_method: str = "totp"
    is_active: bool
    last_login_at: datetime | None = None

    class Config:
        from_attributes = True


class MFATotpSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    manual_entry_key: str


class MFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MFAEmailSetupResponse(BaseModel):
    status: str
    delivery_method: str
    destination: str


class AuthSessionResponse(BaseModel):
    id: str
    device_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    is_active: bool
    last_seen_at: datetime
    created_at: datetime


class AuthStatusResponse(BaseModel):
    brute_force_protection: bool = True
    captcha_enabled: bool = False
    mfa_required: bool = False
    active_sessions: int = 0
    locked_until: datetime | None = None


class EmailGatewayStatusResponse(BaseModel):
    host: str
    port: int
    from_address: str
    tls: bool
    configured: bool


class SSOProviderResponse(BaseModel):
    id: UUID
    name: str
    provider_type: str
    login_url: str
    metadata_url: str | None = None
    client_id: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scope: str | None = None
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


class SSOProviderCreate(BaseModel):
    name: str
    provider_type: str
    login_url: str
    metadata_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_url: str | None = None
    userinfo_url: str | None = None
    scope: str | None = None


class AuthPolicyResponse(BaseModel):
    policy_name: str
    captcha_enabled: bool
    mfa_required: bool
    sso_required: bool
    allow_local_login: bool
    updated_at: datetime

    class Config:
        from_attributes = True


class AuthPolicyUpdate(BaseModel):
    captcha_enabled: bool = False
    mfa_required: bool = False
    sso_required: bool = False
    allow_local_login: bool = True


class UserGroupCreate(BaseModel):
    name: str
    description: str | None = None


class UserGroupResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    created_at: datetime

    class Config:
        from_attributes = True
