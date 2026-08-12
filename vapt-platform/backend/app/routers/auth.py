from datetime import datetime, timedelta, timezone

import os
from urllib.parse import urlencode

import requests
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.auth import AuthPolicy, AuthSession, SSOProvider
from app.models.finding import AuditLog
from app.models.user import User, UserGroup
from app.schemas.auth import (
    AuthSessionResponse,
    AuthPolicyResponse,
    AuthPolicyUpdate,
    AuthStatusResponse,
    EmailGatewayStatusResponse,
    MFAEmailSetupResponse,
    MFATotpSetupResponse,
    MFAVerifyRequest,
    SSOProviderCreate,
    SSOProviderResponse,
    TokenResponse,
    UserCreate,
    UserGroupCreate,
    UserGroupResponse,
    UserUpdate,
    UserResponse,
)
from app.services.auth import create_access_token, hash_password, verify_password
from app.services.ldap_auth import authenticate_ldap
from app.services.mail import email_config_status, send_email_mfa_code, send_welcome_email
from app.services.security import (
    build_otpauth_uri,
    create_auth_session,
    deactivate_session,
    ensure_account_not_locked,
    enforce_roles,
    generate_email_code,
    generate_totp_secret,
    get_auth_policy,
    get_current_user,
    issue_mfa_ticket,
    issue_sso_state,
    record_login_failure,
    reset_login_failures,
    verify_captcha_token,
    verify_totp_code,
    decode_token,
)

router = APIRouter(prefix="/auth", tags=["Auth"])
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:18080")


def _send_welcome_safe(*, email: str, username: str, role: str, temporary_password: str) -> None:
    try:
        send_welcome_email(email=email, username=username, role=role, temporary_password=temporary_password)
    except Exception:
        pass


def _send_email_mfa(user: User) -> None:
    code = generate_email_code()
    user.email_mfa_code = code
    user.email_mfa_expires_at = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=10)
    try:
        send_email_mfa_code(email=user.email, username=user.username, code=code)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Unable to deliver MFA email right now: {exc}") from exc


def _resolve_provider_endpoints(provider: SSOProvider) -> tuple[str, str | None]:
    token_url = provider.token_url
    userinfo_url = provider.userinfo_url
    if provider.metadata_url and provider.provider_type in {"oidc", "oauth2"}:
        try:
            metadata = requests.get(provider.metadata_url, timeout=15).json()
            token_url = token_url or metadata.get("token_endpoint")
            userinfo_url = userinfo_url or metadata.get("userinfo_endpoint")
        except Exception:
            pass
    return token_url, userinfo_url


def _audit(db: Session, *, actor: str, action: str, resource_type: str, resource_id: str, details: dict | None = None) -> None:
    db.add(
        AuditLog(
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
        )
    )


def _upsert_sso_user(db: Session, email: str, username: str, provider: SSOProvider) -> User:
    user = db.query(User).filter((User.email == email) | (User.username == username)).first()
    if not user:
        user = User(
            username=username,
            email=email,
            password_hash="SSO",
            role="viewer",
            auth_source=provider.provider_type,
            mfa_enabled=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        group_name=payload.group_name,
        mfa_delivery_method=payload.mfa_delivery_method,
        mfa_enabled=payload.mfa_delivery_method == "email",
        auth_source="local",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _send_welcome_safe(email=user.email, username=user.username, role=user.role, temporary_password=payload.password)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    otp_code: str | None = Form(default=None),
    captcha_token: str | None = Form(default=None),
    device_name: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    policy = get_auth_policy(db)
    if policy and not policy.allow_local_login:
        raise HTTPException(status_code=403, detail="Local login is disabled. Use configured SSO.")
    if (policy.captcha_enabled if policy else False):
        verify_captcha_token(captcha_token)
    else:
        verify_captcha_token(None)
    user = db.query(User).filter((User.username == username) | (User.email == username)).first()
    if user:
        ensure_account_not_locked(user)

    if user:
        if user.password_hash != "LDAP" and not verify_password(
            password, user.password_hash
        ):
            record_login_failure(db, user)
            raise HTTPException(status_code=401, detail="Invalid credentials")
    else:
        ldap_user = authenticate_ldap(username, password)
        if not ldap_user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user = User(
            username=ldap_user["username"],
            email=ldap_user.get("email", f"{ldap_user['username']}@directory.local"),
            role=ldap_user["role"],
            password_hash="LDAP",
            auth_source="ldap",
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    if user.mfa_enabled:
        if not otp_code:
            if (user.mfa_delivery_method or "totp") == "email":
                _send_email_mfa(user)
                db.commit()
            mfa_ticket, expires_in = issue_mfa_ticket(user.username)
            return TokenResponse(
                requires_mfa=True,
                mfa_ticket=mfa_ticket,
                expires_in=expires_in,
                device_name=device_name,
            )
        valid_code = verify_totp_code(user.mfa_secret, otp_code)
        if (user.mfa_delivery_method or "totp") == "email":
            valid_code = bool(
                user.email_mfa_code
                and user.email_mfa_code == otp_code
                and user.email_mfa_expires_at
                and user.email_mfa_expires_at > datetime.now(timezone.utc)
            )
        if not valid_code:
            record_login_failure(db, user)
            raise HTTPException(status_code=401, detail="Invalid multi-factor authentication code")
        user.email_mfa_code = None
        user.email_mfa_expires_at = None

    reset_login_failures(db, user)
    session = create_auth_session(
        db,
        user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        device_name=device_name or request.headers.get("x-device-name") or "Browser session",
    )
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = request.client.host if request.client else None
    user.last_login_user_agent = request.headers.get("user-agent")
    db.commit()

    access_token, expires_in = create_access_token({"sub": user.username, "role": user.role, "sid": session.session_token})
    _audit(
        db,
        actor=user.username,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        details={"ip_address": user.last_login_ip, "device_name": session.device_name, "auth_source": user.auth_source},
    )
    db.commit()
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "session_id": str(session.id),
        "device_name": session.device_name,
    }


@router.get("/me", response_model=UserResponse)
def read_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/status", response_model=AuthStatusResponse)
def read_auth_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    active_sessions = db.query(AuthSession).filter(AuthSession.user_id == current_user.id, AuthSession.is_active.is_(True)).count()
    policy = get_auth_policy(db)
    return AuthStatusResponse(
        brute_force_protection=True,
        captcha_enabled=policy.captcha_enabled if policy else False,
        mfa_required=(policy.mfa_required if policy else False) or current_user.mfa_enabled,
        active_sessions=active_sessions,
        locked_until=current_user.locked_until,
    )


@router.get("/sessions", response_model=list[AuthSessionResponse])
def list_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = (
        db.query(AuthSession)
        .filter(AuthSession.user_id == current_user.id)
        .order_by(AuthSession.created_at.desc())
        .all()
    )
    return [
        AuthSessionResponse(
            id=str(session.id),
            device_name=session.device_name,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            is_active=session.is_active,
            last_seen_at=session.last_seen_at,
            created_at=session.created_at,
        )
        for session in sessions
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    deactivate_session(db, current_user, session_id)


@router.post("/mfa/setup", response_model=MFATotpSetupResponse)
def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    secret = generate_totp_secret()
    current_user.mfa_secret = secret
    current_user.mfa_enabled = False
    db.commit()
    return MFATotpSetupResponse(
        secret=secret,
        otpauth_url=build_otpauth_uri(current_user.username, secret),
        manual_entry_key=secret,
    )


@router.post("/mfa/setup-email", response_model=MFAEmailSetupResponse)
def setup_email_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current_user.mfa_enabled = True
    current_user.mfa_delivery_method = "email"
    _send_email_mfa(current_user)
    db.commit()
    db.refresh(current_user)
    return MFAEmailSetupResponse(status="enabled", delivery_method="email", destination=current_user.email)


@router.post("/mfa/verify", response_model=UserResponse)
def verify_mfa(
    payload: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_totp_code(current_user.mfa_secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    current_user.mfa_enabled = True
    current_user.mfa_delivery_method = "totp"
    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/mfa/disable", response_model=UserResponse)
def disable_mfa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.email_mfa_code = None
    current_user.email_mfa_expires_at = None
    db.commit()
    db.refresh(current_user)
    return current_user


@router.get("/admin/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    return db.query(User).order_by(User.created_at.desc()).all()


@router.patch("/admin/users/{user_id}", response_model=UserResponse)
def update_admin_user(
    user_id: str,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.group_name:
        group = db.query(UserGroup).filter(UserGroup.name == payload.group_name).first()
        if not group:
            raise HTTPException(status_code=404, detail="User group not found")

    if payload.username and payload.username != user.username:
        exists = db.query(User).filter(User.username == payload.username).first()
        if exists:
            raise HTTPException(status_code=409, detail="Username already exists")
        user.username = payload.username

    if payload.email and payload.email != user.email:
        exists = db.query(User).filter(User.email == payload.email).first()
        if exists:
            raise HTTPException(status_code=409, detail="Email already exists")
        user.email = payload.email

    if payload.password:
        user.password_hash = hash_password(payload.password)

    if payload.role:
        user.role = payload.role

    if payload.group_name is not None:
        user.group_name = payload.group_name or None

    if payload.is_active is not None:
        user.is_active = payload.is_active

    if payload.mfa_delivery_method:
        user.mfa_delivery_method = payload.mfa_delivery_method
        if payload.mfa_delivery_method == "email":
            user.mfa_enabled = True if payload.mfa_enabled is None else payload.mfa_enabled
            user.mfa_secret = None
        elif payload.mfa_delivery_method == "totp":
            user.email_mfa_code = None
            user.email_mfa_expires_at = None
            if payload.mfa_enabled is not None:
                user.mfa_enabled = payload.mfa_enabled

    if payload.mfa_enabled is not None:
        user.mfa_enabled = payload.mfa_enabled
        if not payload.mfa_enabled:
            user.mfa_secret = None
            user.email_mfa_code = None
            user.email_mfa_expires_at = None

    _audit(
        db,
        actor=current_user.username,
        action="user.update",
        resource_type="user",
        resource_id=user.id,
        details={
            "username": user.username,
            "role": user.role,
            "group_name": user.group_name,
            "mfa_delivery_method": user.mfa_delivery_method,
            "is_active": user.is_active,
        },
    )
    db.commit()
    db.refresh(user)
    return user


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_admin_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    if str(current_user.id) == str(user_id):
        raise HTTPException(status_code=400, detail="You cannot delete your own active account.")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.query(AuthSession).filter(AuthSession.user_id == user.id).delete(synchronize_session=False)
    _audit(
        db,
        actor=current_user.username,
        action="user.delete",
        resource_type="user",
        resource_id=user.id,
        details={"username": user.username, "email": user.email, "role": user.role},
    )
    db.delete(user)
    db.commit()
    return None


@router.post("/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_admin_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")
    if payload.group_name:
        group = db.query(UserGroup).filter(UserGroup.name == payload.group_name).first()
        if not group:
            raise HTTPException(status_code=404, detail="User group not found")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
        group_name=payload.group_name,
        mfa_delivery_method=payload.mfa_delivery_method,
        mfa_enabled=payload.mfa_delivery_method == "email",
        auth_source="local",
    )
    db.add(user)
    db.flush()
    _audit(
        db,
        actor=current_user.username,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        details={"username": user.username, "role": user.role, "group_name": user.group_name},
    )
    db.commit()
    db.refresh(user)
    _send_welcome_safe(email=user.email, username=user.username, role=user.role, temporary_password=payload.password)
    return user


@router.get("/admin/email/status", response_model=EmailGatewayStatusResponse)
def get_email_gateway_status(
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    return EmailGatewayStatusResponse(**email_config_status())


@router.get("/admin/groups", response_model=list[UserGroupResponse])
def list_user_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    return db.query(UserGroup).order_by(UserGroup.name.asc()).all()


@router.post("/admin/groups", response_model=UserGroupResponse, status_code=status.HTTP_201_CREATED)
def create_user_group(
    payload: UserGroupCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    existing = db.query(UserGroup).filter(UserGroup.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="User group already exists")
    group = UserGroup(name=payload.name, description=payload.description)
    db.add(group)
    _audit(
        db,
        actor=current_user.username,
        action="group.create",
        resource_type="group",
        resource_id=payload.name,
        details={"description": payload.description},
    )
    db.commit()
    db.refresh(group)
    return group


@router.get("/sso/providers", response_model=list[SSOProviderResponse])
def list_sso_providers(db: Session = Depends(get_db)):
    return db.query(SSOProvider).filter(SSOProvider.enabled.is_(True)).order_by(SSOProvider.created_at.desc()).all()


@router.get("/policy", response_model=AuthPolicyResponse)
def read_auth_policy(db: Session = Depends(get_db)):
    policy = get_auth_policy(db)
    if not policy:
        policy = AuthPolicy(policy_name="default", captcha_enabled=False, mfa_required=False, sso_required=False, allow_local_login=True)
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


@router.post("/admin/sso/providers", response_model=SSOProviderResponse)
def create_sso_provider(
    payload: SSOProviderCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    provider = SSOProvider(
        name=payload.name,
        provider_type=payload.provider_type,
        login_url=payload.login_url,
        metadata_url=payload.metadata_url,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        token_url=payload.token_url,
        userinfo_url=payload.userinfo_url,
        scope=payload.scope,
        enabled=True,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return provider


@router.post("/admin/sso/providers/{provider_id}/toggle", response_model=SSOProviderResponse)
def toggle_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    provider = db.get(SSOProvider, provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    provider.enabled = not provider.enabled
    db.commit()
    db.refresh(provider)
    return provider


@router.post("/admin/policy", response_model=AuthPolicyResponse)
def update_auth_policy(
    payload: AuthPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    policy = get_auth_policy(db)
    if not policy:
        policy = AuthPolicy(policy_name="default")
        db.add(policy)
    policy.captcha_enabled = payload.captcha_enabled
    policy.mfa_required = payload.mfa_required
    policy.sso_required = payload.sso_required
    policy.allow_local_login = payload.allow_local_login
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/sso/{provider_id}/start")
def start_sso_login(provider_id: str, db: Session = Depends(get_db)):
    provider = db.get(SSOProvider, provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    state, _ = issue_sso_state(provider_id)
    redirect_uri = f"{FRONTEND_BASE_URL}/login?sso_callback=1&provider={provider_id}"
    params = {
        "response_type": "code",
        "client_id": provider.client_id or "",
        "redirect_uri": redirect_uri,
        "scope": provider.scope or "openid profile email",
        "state": state,
    }
    return {"redirect_url": f"{provider.login_url}?{urlencode(params)}"}


@router.get("/sso/{provider_id}/callback", response_model=TokenResponse)
def complete_sso_login(
    provider_id: str,
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    device_name: str | None = Query(default="SSO browser"),
    db: Session = Depends(get_db),
):
    provider = db.get(SSOProvider, provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    try:
        payload = decode_token(state)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid SSO state") from exc
    if payload.get("type") != "sso_state" or payload.get("provider_id") != provider_id:
        raise HTTPException(status_code=400, detail="SSO state validation failed")

    token_url, userinfo_url = _resolve_provider_endpoints(provider)
    if provider.provider_type in {"oidc", "oauth2"} and token_url and provider.client_id and provider.client_secret:
        redirect_uri = f"{FRONTEND_BASE_URL}/login?sso_callback=1&provider={provider_id}"
        token_response = requests.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            },
            timeout=20,
        )
        token_response.raise_for_status()
        token_payload = token_response.json()
        access_token_value = token_payload.get("access_token")
        if not access_token_value:
            raise HTTPException(status_code=400, detail="SSO token exchange did not return an access token")
        profile_payload = {}
        if userinfo_url:
            profile_response = requests.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token_value}"},
                timeout=20,
            )
            profile_response.raise_for_status()
            profile_payload = profile_response.json()
        email = profile_payload.get("email") or f"sso-{provider_id[:8]}-{code[:6]}@sso.local"
        username = (
            profile_payload.get("preferred_username")
            or profile_payload.get("name")
            or email.split("@")[0]
        )
        user = _upsert_sso_user(db, email, username, provider)
    else:
        raise HTTPException(status_code=400, detail="This provider is not fully configured for callback-based SSO.")

    session = create_auth_session(
        db,
        user,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        device_name=device_name,
    )
    access_token, expires_in = create_access_token({"sub": user.username, "role": user.role, "sid": session.session_token})
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        session_id=str(session.id),
        device_name=session.device_name,
    )
