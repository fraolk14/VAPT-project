import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import pyotp

from app.database import get_db
from app.models.auth import AuthPolicy, AuthSession
from app.models.user import User


SECRET_KEY = os.getenv("JWT_SECRET", "development-secret-change-me")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
LOGIN_CAPTCHA_ENABLED = os.getenv("LOGIN_CAPTCHA_ENABLED", "false").lower() == "true"
CAPTCHA_BYPASS_TOKEN = os.getenv("CAPTCHA_BYPASS_TOKEN", "vapt-human")
SSO_STATE_EXPIRE_MINUTES = int(os.getenv("SSO_STATE_EXPIRE_MINUTES", "10"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_access_token(data: dict) -> tuple[str, int]:
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.now(timezone.utc) + expires_delta
    to_encode = data.copy()
    to_encode.update({"exp": expires_at})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token, int(expires_delta.total_seconds())


def issue_mfa_ticket(username: str) -> tuple[str, int]:
    expires_delta = timedelta(minutes=10)
    expires_at = datetime.now(timezone.utc) + expires_delta
    payload = {
        "sub": username,
        "type": "mfa",
        "nonce": secrets.token_hex(8),
        "exp": expires_at,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, int(expires_delta.total_seconds())


def issue_sso_state(provider_id: str) -> tuple[str, int]:
    expires_delta = timedelta(minutes=SSO_STATE_EXPIRE_MINUTES)
    expires_at = datetime.now(timezone.utc) + expires_delta
    payload = {
        "provider_id": provider_id,
        "type": "sso_state",
        "nonce": secrets.token_hex(12),
        "exp": expires_at,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, int(expires_delta.total_seconds())


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def verify_captcha_token(captcha_token: str | None) -> None:
    if LOGIN_CAPTCHA_ENABLED and (captcha_token or "").strip() != CAPTCHA_BYPASS_TOKEN:
        raise HTTPException(status_code=400, detail="Captcha validation failed")


def get_auth_policy(db: Session) -> AuthPolicy | None:
    return db.query(AuthPolicy).filter(AuthPolicy.policy_name == "default").first()


def ensure_account_not_locked(user: User) -> None:
    locked_until = user.locked_until
    if locked_until and locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=423, detail="Account temporarily locked due to repeated failed sign-in attempts")


def record_login_failure(db: Session, user: User | None) -> None:
    if not user:
        return
    user.failed_login_attempts = int(user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
    db.commit()


def reset_login_failures(db: Session, user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_otpauth_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="VAPT Command Center")


def verify_totp_code(secret: str | None, code: str) -> bool:
    if not secret:
        return False
    return bool(pyotp.TOTP(secret).verify(code, valid_window=1))


def generate_email_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def create_auth_session(
    db: Session,
    user: User,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
    device_name: str | None = None,
) -> AuthSession:
    session = AuthSession(
        user_id=user.id,
        session_token=secrets.token_urlsafe(24),
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def touch_auth_session(db: Session, session_token: str | None) -> None:
    if not session_token:
        return
    session = db.query(AuthSession).filter(AuthSession.session_token == session_token, AuthSession.is_active.is_(True)).first()
    if not session:
        return
    session.last_seen_at = datetime.now(timezone.utc)
    db.commit()


def deactivate_session(db: Session, user: User, session_id: str) -> None:
    session = db.query(AuthSession).filter(AuthSession.id == session_id, AuthSession.user_id == user.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    session.is_active = False
    db.commit()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    if payload.get("type") == "mfa":
        raise credentials_exception

    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if not user:
        raise credentials_exception
    touch_auth_session(db, payload.get("sid"))
    return user


def enforce_roles(current_user: User, *roles: str) -> None:
    if roles and current_user.role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{current_user.role}' is not permitted for this action",
        )
