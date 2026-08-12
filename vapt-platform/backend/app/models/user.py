import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base
from app.models.iam import user_group_association


class UserGroup(Base):
    __tablename__ = "user_groups"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    tenant_id = Column(String, nullable=False, default="default", index=True)
    group_name = Column(String, nullable=True, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer", nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    auth_source = Column(String, default="local", nullable=False)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String, nullable=True)
    mfa_delivery_method = Column(String, default="totp", nullable=False)
    email_mfa_code = Column(String, nullable=True)
    email_mfa_expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String, nullable=True)
    last_login_user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

    role_obj = relationship("Role")
    groups_rel = relationship("Group", secondary=user_group_association, back_populates="users")
    policies = relationship("Policy", back_populates="user", cascade="all, delete-orphan")
