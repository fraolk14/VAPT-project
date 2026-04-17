import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class MonitoringRule(Base):
    __tablename__ = "monitoring_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, index=True)
    event_source = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    target_match = Column(String, nullable=True)
    action = Column(String, nullable=False, default="queue_scan")
    tool = Column(String, nullable=False, default="openvas")
    enabled = Column(Boolean, nullable=False, default=True)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MonitoringEvent(Base):
    __tablename__ = "monitoring_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    target = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="medium")
    status = Column(String, nullable=False, default="received")
    payload = Column(JSON, nullable=False, default=dict)
    triggered_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="medium")
    status = Column(String, nullable=False, default="open")
    target = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    related_finding_ids = Column(JSON, nullable=False, default=list)
    metadata_json = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ComplianceTemplate(Base):
    __tablename__ = "compliance_templates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False, unique=True, index=True)
    framework = Column(String, nullable=False, index=True)
    controls = Column(JSON, nullable=False, default=list)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ComplianceAssessment(Base):
    __tablename__ = "compliance_assessments"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    template_id = Column(UUID(as_uuid=True), ForeignKey("compliance_templates.id"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False, default="draft")
    score = Column(String, nullable=False, default="0")
    summary = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
