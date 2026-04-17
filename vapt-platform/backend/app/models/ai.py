import uuid

from sqlalchemy import Column, DateTime, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class AIAnalysisCache(Base):
    __tablename__ = "ai_analysis_cache"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cache_key = Column(String, nullable=False, unique=True, index=True)
    analysis_type = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, default="local-fallback")
    model = Column(String, nullable=False, default="operator-playbook")
    input_fingerprint = Column(String, nullable=False, index=True)
    request_payload = Column(JSON, nullable=False, default=dict)
    response_payload = Column(JSON, nullable=False, default=dict)
    hit_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AIDecisionLog(Base):
    __tablename__ = "ai_decision_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_type = Column(String, nullable=False, index=True)
    actor = Column(String, nullable=False, index=True)
    provider = Column(String, nullable=False, default="local-fallback")
    model = Column(String, nullable=False, default="operator-playbook")
    cache_key = Column(String, nullable=True, index=True)
    input_fingerprint = Column(String, nullable=False, index=True)
    request_payload = Column(JSON, nullable=False, default=dict)
    response_payload = Column(JSON, nullable=False, default=dict)
    decision_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
