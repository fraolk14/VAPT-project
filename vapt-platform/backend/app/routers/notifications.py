from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.notification import Notification
from app.models.user import User
from app.services.notifications import serialize
from app.services.security import get_current_user

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("")
def list_notifications(
    limit: int = Query(default=30, ge=1, le=100),
    unread_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """The signed-in user's notifications, newest first, with the unread count for the bell."""
    q = db.query(Notification).filter(Notification.username == current_user.username)
    unread = q.filter(Notification.read_at.is_(None)).count()
    if unread_only:
        q = q.filter(Notification.read_at.is_(None))
    items = q.order_by(Notification.created_at.desc()).limit(limit).all()
    return {"unread": unread, "items": [serialize(n) for n in items]}


@router.post("/{notification_id}/read")
def mark_read(notification_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    n = db.query(Notification).filter(Notification.id == notification_id, Notification.username == current_user.username).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    if n.read_at is None:
        n.read_at = datetime.now(timezone.utc)
        db.commit()
    return serialize(n)


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    count = (
        db.query(Notification)
        .filter(Notification.username == current_user.username, Notification.read_at.is_(None))
        .update({Notification.read_at: datetime.now(timezone.utc)}, synchronize_session=False)
    )
    db.commit()
    return {"marked": count}
