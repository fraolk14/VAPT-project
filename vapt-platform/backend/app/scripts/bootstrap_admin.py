"""Create or recover the platform administrator account.

Usage (inside the api container):
    python -m app.scripts.bootstrap_admin            # create 'admin' if no admin exists
    python -m app.scripts.bootstrap_admin --reset    # set a new random password for 'admin' and unlock it

The new password is printed once. Change it after signing in.
"""
import secrets
import sys

from app.database import SessionLocal
from app.models.user import User
from app.services.demo_seed import _ensure_bootstrap_admin
from app.services.security import hash_password


def main() -> int:
    db = SessionLocal()
    try:
        if "--reset" not in sys.argv:
            _ensure_bootstrap_admin(db)
            return 0
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            print("No 'admin' user exists; run without --reset to create one.")
            return 1
        password = secrets.token_urlsafe(16)
        admin.password_hash = hash_password(password)
        admin.failed_login_attempts = 0
        admin.locked_until = None
        admin.is_active = True
        db.commit()
        print(f"Admin password reset. New password: {password}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
