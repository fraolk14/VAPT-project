import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Table, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


user_group_association = Table(
    "user_group_association",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("group_id", Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True),
)


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    permissions = Column(JSON, nullable=False, default=dict)
    description = Column(String, nullable=True)


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    users = relationship("User", secondary=user_group_association, back_populates="groups_rel")
    policies = relationship("Policy", back_populates="group", cascade="all, delete-orphan")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True)
    finding_scope = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="policies", foreign_keys=[user_id])
    group = relationship("Group", back_populates="policies", foreign_keys=[group_id])


class SSOConfig(Base):
    __tablename__ = "sso_config"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, unique=True, nullable=False, index=True)
    client_id = Column(String, nullable=True)
    client_secret = Column(String, nullable=True)
    issuer_url = Column(String, nullable=True)
    metadata_url = Column(String, nullable=True)
    is_enabled = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
