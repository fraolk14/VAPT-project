from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.user import User
from app.services.auth import hash_password
import uuid

def bootstrap_admin():
    db: Session = SessionLocal()

    admin = db.query(User).filter(User.username == "admin").first()
    if admin:
        return

    admin = User(
        id=str(uuid.uuid4()),
        username="admin",
        password_hash=hash_password("Admin@123"),
        role="admin"
    )

    db.add(admin)
    db.commit()

if __name__ == "__main__":
    bootstrap_admin()
