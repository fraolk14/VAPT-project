import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class Organization(Base):
    __tablename__ = "organization"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_jobs = relationship("ScanJob", back_populates="organization", cascade="all, delete-orphan")


class ScanJob(Base):
    __tablename__ = "scan_job"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organization.id"), nullable=True)
    scope = Column(String, nullable=False)  # e.g., "192.168.1.0/24"
    scope_type = Column(String, nullable=False)  # "IP", "CIDR", "Domain", "ASN", "URL", "Range", "Cloud"
    status = Column(String, default="PENDING", nullable=False)  # "PENDING", "RUNNING", "COMPLETED", "FAILED"
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="scan_jobs")
    assets = relationship("MisconfigAsset", back_populates="scan_job", cascade="all, delete-orphan")


class MisconfigAsset(Base):
    __tablename__ = "misconfig_asset"

    id = Column(Integer, primary_key=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_job.id"), nullable=False)
    ip = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    asset_type = Column(String, nullable=False)  # "OS", "Network", "Website", "Endpoint"
    os_type = Column(String, nullable=True)  # "Linux", "Windows", "macOS", "RouterOS", "Unknown"
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_job = relationship("ScanJob", back_populates="assets")
    misconfigurations = relationship("Misconfiguration", back_populates="asset", cascade="all, delete-orphan")


class Misconfiguration(Base):
    __tablename__ = "misconfiguration"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("misconfig_asset.id"), nullable=False)
    issue = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    cve = Column(String, nullable=True)
    detected_by = Column(String, nullable=False)  # "Lynis", "Nmap", "Nuclei", "ZAP", "SecurityHeaders", "SSLLabs"
    remediation = Column(Text, nullable=True)
    status = Column(String, default="OPEN", nullable=False)  # "OPEN", "IN_PROGRESS", "FIXED"
    discovered_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    asset = relationship("MisconfigAsset", back_populates="misconfigurations")
