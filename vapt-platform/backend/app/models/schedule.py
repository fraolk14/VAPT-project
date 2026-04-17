import uuid

from sqlalchemy import Boolean, Column, DateTime, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_name = Column(String, nullable=False, index=True)
    scan_type = Column(String, nullable=False, index=True)
    tool = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False)
    profile = Column(String, nullable=False, default="standard")
    cadence_minutes = Column(String, nullable=False, default="60")
    options = Column(JSON, default=dict, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
