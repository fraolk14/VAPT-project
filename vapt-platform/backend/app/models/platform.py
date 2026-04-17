import secrets
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class PluginRegistration(Base):
    __tablename__ = "plugin_registrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    plugin_type = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False, default="1.0.0")
    entrypoint = Column(String, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    capabilities = Column(JSON, nullable=False, default=list)
    config = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PublicApiKey(Base):
    __tablename__ = "public_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    key_prefix = Column(String, nullable=False, unique=True, index=True)
    key_hash = Column(String, nullable=False)
    role_scope = Column(String, nullable=False, default="analyst")
    enabled = Column(Boolean, nullable=False, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DevSecOpsHook(Base):
    __tablename__ = "devsecops_hooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    project_name = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    secret_hash = Column(String, nullable=False)
    secret_hint = Column(String, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    events = relationship("DevSecOpsEvent", back_populates="hook")

    @staticmethod
    def generate_secret() -> str:
        return f"vapt-hook-{secrets.token_urlsafe(24)}"


class DevSecOpsEvent(Base):
    __tablename__ = "devsecops_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hook_id = Column(UUID(as_uuid=True), ForeignKey("devsecops_hooks.id"), nullable=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="received")
    summary = Column(Text, nullable=True)
    payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    hook = relationship("DevSecOpsHook", back_populates="events")


class EndpointSoftwareInventory(Base):
    __tablename__ = "endpoint_software_inventory"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    endpoint_name = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=True, index=True)
    ip_address = Column(String, nullable=True, index=True)
    os_name = Column(String, nullable=True)
    source = Column(String, nullable=False, default="agent")
    reported_by = Column(String, nullable=True)
    installed_apps = Column(JSON, nullable=False, default=list)
    approved_baseline = Column(JSON, nullable=False, default=list)
    detected_apps = Column(JSON, nullable=False, default=list)
    status = Column(String, nullable=False, default="received")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
