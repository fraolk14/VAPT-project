import uuid

from sqlalchemy import Boolean, Column, DateTime, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    channel = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    min_severity = Column(String, nullable=False, default="high")
    scan_tool = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    metadata_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_name = Column(String, nullable=False)
    channel = Column(String, nullable=False)
    destination = Column(String, nullable=False)
    finding_id = Column(String, nullable=True)
    status = Column(String, nullable=False, default="queued")
    payload = Column(JSON, default=dict, nullable=False)
    response_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
