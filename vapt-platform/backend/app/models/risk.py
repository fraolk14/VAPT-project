import uuid
from sqlalchemy import Column, String, Float, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from app.database import Base


class Risk(Base):
    __tablename__ = "risks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"))
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    recommendation = Column(String)
    calculated_at = Column(DateTime(timezone=True), server_default=func.now())
