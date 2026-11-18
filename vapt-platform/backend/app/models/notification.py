import uuid

from sqlalchemy import Column, DateTime, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class Notification(Base):
    """One in-app notification for one user (the bell in the navbar).

    `ref` identifies what it is about (a finding id, a CVE id, a digest key), so the same event is
    never delivered to the same user twice.
    """

    __tablename__ = "notifications"
    __table_args__ = (UniqueConstraint("username", "kind", "ref", name="uq_notification_user_kind_ref"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, nullable=False, index=True)
    kind = Column(String, nullable=False, index=True)  # finding_assigned | new_cve | cve_digest
    ref = Column(String, nullable=False)
    title = Column(String, nullable=False)
    body = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    link = Column(String, nullable=True)  # in-app route, e.g. /findings/<id>
    data = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    read_at = Column(DateTime(timezone=True), nullable=True)
