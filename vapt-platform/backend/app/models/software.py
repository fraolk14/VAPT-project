import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Software(Base):
    __tablename__ = "software"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Core Info
    name = Column(String, nullable=False, index=True)  # e.g., "Apache HTTP Server"
    vendor = Column(String, nullable=True)  # e.g., "Apache Software Foundation"
    version = Column(String, nullable=True)  # e.g., "2.4.49"
    category = Column(String, nullable=False, default="OS")  # "Web", "OS", "Network", "Mobile"
    cpe = Column(String, nullable=True)  # Common Platform Enumeration

    # Governance
    status = Column(String, default="UNAUTHORIZED", nullable=False)  # "APPROVED", "VULNERABLE", "UNAUTHORIZED"
    risk_score = Column(Float, default=0.0, nullable=False)  # Calculated based on CVEs
    cves = Column(JSON, default=list, nullable=False)  # List of CVE IDs found via NVD
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

    assets_rel = relationship("SoftwareAsset", back_populates="software", cascade="all, delete-orphan")


class SoftwareAsset(Base):
    __tablename__ = "software_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    software_id = Column(Integer, ForeignKey("software.id"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    ip_address = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True)
    endpoint_name = Column(String, nullable=True)
    source = Column(String, nullable=False, default="Nmap -sV")  # "WMI", "Nmap -sV", "Lynis", "Banner Probe", "Asset Scan"
    installed_path = Column(String, nullable=True)  # e.g., "C:\Program Files\Apache" or "Port 80"
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    software = relationship("Software", back_populates="assets_rel")
    asset = relationship("Asset")


class WhitelistSoftware(Base):
    __tablename__ = "whitelist_software"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False, index=True)
    vendor = Column(String, nullable=True)
    reason = Column(String, nullable=True)  # e.g., "Approved by Security Team"
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
