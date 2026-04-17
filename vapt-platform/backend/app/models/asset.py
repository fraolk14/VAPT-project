import uuid

from sqlalchemy import Column, DateTime, Float, JSON, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_name = Column(String, nullable=False)
    tenant_id = Column(String, nullable=False, default="default", index=True)
    ip_address = Column(String, index=True, nullable=False)
    url = Column(String, nullable=True)
    hostname = Column(String)
    os = Column(String)
    asset_type = Column(String, nullable=False)
    environment = Column(String, default="prod", nullable=False)
    criticality = Column(String, default="medium", nullable=False)
    owner = Column(String)
    exposure = Column(String, default="internal", nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    cloud_provider = Column(String)
    business_unit = Column(String)
    risk_score = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
