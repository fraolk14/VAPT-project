import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
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


class ScanJobModel(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, default="Unnamed Scan")
    engine = Column(String, nullable=False, default="Network")  # "Network", "Web", "Mobile"
    target = Column(String, nullable=False)
    target_type = Column(String, nullable=False, default="IP")  # "IP", "Domain", "CIDR", "URL", "APK"
    status = Column(String, default="PENDING", nullable=False)  # "PENDING", "RUNNING", "COMPLETED", "FAILED"
    progress = Column(Integer, default=0, nullable=False)
    scheduled_at = Column(DateTime(timezone=True), nullable=True)
    schedule_interval = Column(String, nullable=True)  # "Daily", "Weekly", "Monthly"
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)

    asset = relationship("Asset")
    user = relationship("User")
