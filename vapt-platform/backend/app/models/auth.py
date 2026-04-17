import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    session_token = Column(String, nullable=False, unique=True, index=True)
    device_name = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SSOProvider(Base):
    __tablename__ = "sso_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    provider_type = Column(String, nullable=False, index=True)
    login_url = Column(String, nullable=False)
    metadata_url = Column(String, nullable=True)
    client_id = Column(String, nullable=True)
    client_secret = Column(Text, nullable=True)
    token_url = Column(String, nullable=True)
    userinfo_url = Column(String, nullable=True)
    scope = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuthPolicy(Base):
    __tablename__ = "auth_policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_name = Column(String, nullable=False, unique=True, index=True)
    captcha_enabled = Column(Boolean, default=False, nullable=False)
    mfa_required = Column(Boolean, default=False, nullable=False)
    sso_required = Column(Boolean, default=False, nullable=False)
    allow_local_login = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
