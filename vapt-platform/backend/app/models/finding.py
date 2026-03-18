import uuid

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True, index=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=True)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)
    source = Column(String, nullable=False)
    status = Column(String, default="open", nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String, nullable=False)
    service = Column(String, nullable=True)
    state = Column(String, nullable=False)
    cve_id = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    confidence = Column(Float, default=0.5, nullable=False)
    evidence = Column(Text)
    remediation = Column(Text)
    compliance_map = Column(JSON, default=list, nullable=False)
    finding_metadata = Column(JSON, default=dict, nullable=False)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor = Column(String, nullable=False)
    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    outcome = Column(String, default="success", nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
