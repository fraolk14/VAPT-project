import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, Float, Integer, JSON, String, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_name = Column(String, nullable=False, default="Unnamed Asset")
    tenant_id = Column(String, nullable=False, default="default", index=True)
    hostname = Column(String, nullable=False, default="")
    ip_address = Column(String, index=True, nullable=False, default="")
    url = Column(String, nullable=True)
    os = Column(String, nullable=True)
    os_type = Column(String, nullable=True)
    
    owner = Column(String, nullable=True)  # Email address
    environment = Column(String, default="Production", nullable=False)  # "Production", "Staging", "Development", "Test"
    criticality = Column(String, default="Medium", nullable=False)  # "Critical", "High", "Medium", "Low"
    risk_level = Column(String, default="Medium", nullable=False)  # "High", "Medium", "Low"
    risk_score = Column(Float, default=0.0, nullable=False)

    classification = Column(String, default="Internal", nullable=False)  # "Internal" or "External"
    exposure = Column(String, default="internal", nullable=False)  # Alias/legacy exposure
    asset_type = Column(String, nullable=False, default="OS")  # "OS", "Network", "Website", "Endpoint"
    
    tags = Column(JSON, default=list, nullable=False)
    cloud_provider = Column(String, nullable=True)
    business_unit = Column(String, nullable=True)
    
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    last_scan_id = Column(Integer, ForeignKey("scan_job.id"), nullable=True)

    scan_job = relationship("ScanJob", foreign_keys=[last_scan_id])
