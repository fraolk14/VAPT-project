import uuid

from sqlalchemy import Column, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_name = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False, index=True)
    tool = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="queued", index=True)
    target = Column(String, nullable=False)
    profile = Column(String, default="standard", nullable=False)
    schedule = Column(String)
    triggered_by = Column(String, ForeignKey("users.id"), nullable=True)
    tenant_id = Column(String, default="default", nullable=False, index=True)
    correlation_id = Column(String, default=lambda: str(uuid.uuid4()), nullable=False)
    progress = Column(String, default="0", nullable=False)
    engine_metadata = Column(JSON, default=dict, nullable=False)
    result_summary = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text)
    started_at = Column(DateTime(timezone=True))
    finished_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanTarget(Base):
    __tablename__ = "scan_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending", nullable=False)
    target_metadata = Column(JSON, default=dict, nullable=False)
