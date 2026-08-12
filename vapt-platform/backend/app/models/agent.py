import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class AgentDevice(Base):
    __tablename__ = "agent_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(String, unique=True, nullable=False, index=True)
    hostname = Column(String, nullable=False)
    hardware_id = Column(String, nullable=True)
    credential_hash = Column(String, nullable=False)  # Bcrypt hash of per-device API key (never plaintext)
    enrollment_token_ref = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)  # "active", "revoked"
    ip_address = Column(String, nullable=True)
    os_info = Column(String, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String, unique=True, nullable=False, index=True)
    created_by = Column(String, nullable=True, default="admin")
    is_used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class SoftwareAllowlist(Base):
    __tablename__ = "software_allowlist"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False, index=True)
    vendor = Column(String, nullable=True)
    reason = Column(String, nullable=True)
    category = Column(String, nullable=False, default="Approved")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
