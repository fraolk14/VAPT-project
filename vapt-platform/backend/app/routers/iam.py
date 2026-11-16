import re
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.auth import AuthPolicy, AuthSession, SSOProvider
from app.models.finding import AuditLog
from app.models.iam import Group, Policy, Role, SSOConfig
from app.models.user import User
from app.services.security import access_code_configured, access_code_required, get_current_user, hash_password, normalize_role

# Mounted with ADMIN_ONLY in main.py: every route here requires an administrator.
router = APIRouter(prefix="/iam", tags=["Identity & Access Management Engine"])

MIN_PASSWORD_LENGTH = 12
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def seed_default_roles_if_empty(db: Session):
    if db.query(Role).count() == 0:
        default_roles = [
            {"name": "Admin", "description": "Full access: users, scans, findings, settings.",
             "permissions": {"view_findings": True, "edit_findings": True, "manage_users": True, "view_reports": True, "run_scans": True}},
            {"name": "SecurityEngineer", "description": "Runs scans, triages and remediates findings, manages alert rules.",
             "permissions": {"view_findings": True, "edit_findings": True, "manage_users": False, "view_reports": True, "run_scans": True}},
            {"name": "Auditor", "description": "Read-only access to posture, findings, reports and evidence.",
             "permissions": {"view_findings": True, "edit_findings": False, "manage_users": False, "view_reports": True, "run_scans": False}},
            {"name": "Viewer", "description": "Read-only access to dashboards and findings.",
             "permissions": {"view_findings": True, "edit_findings": False, "manage_users": False, "view_reports": False, "run_scans": False}},
        ]
        for r in default_roles:
            db.add(Role(name=r["name"], description=r["description"], permissions=r["permissions"]))
        db.commit()


def _audit(db: Session, actor: User, action: str, target: User | None, details: dict[str, Any]) -> None:
    db.add(AuditLog(actor=actor.username, action=action, resource_type="user",
                    resource_id=str(target.id) if target else "-", details={"username": target.username if target else None, **details}))


def _is_admin(user: User) -> bool:
    return normalize_role(user.role) == "admin"


def _active_admins(db: Session) -> list[User]:
    return [u for u in db.query(User).filter(User.is_active.is_(True)).all() if _is_admin(u)]


def _guard_admin_change(db: Session, actor: User, target: User, *, removes_admin: bool, action: str) -> None:
    """Stop an admin from locking themselves out or removing the last active admin."""
    if target.id == actor.id and removes_admin:
        raise HTTPException(status_code=400, detail=f"You can't {action} your own account. Ask another administrator.")
    if removes_admin and _is_admin(target) and target.is_active and len(_active_admins(db)) <= 1:
        raise HTTPException(status_code=400, detail=f"Can't {action} the last active administrator.")


def _revoke_sessions(db: Session, user: User) -> int:
    sessions = db.query(AuthSession).filter(AuthSession.user_id == user.id, AuthSession.is_active.is_(True)).all()
    for s in sessions:
        s.is_active = False
    return len(sessions)


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")


def _role_for(db: Session, role_id: int | None) -> tuple[int | None, str]:
    role_obj = db.get(Role, role_id) if role_id else None
    if role_id and not role_obj:
        raise HTTPException(status_code=400, detail="Unknown role.")
    return (role_obj.id if role_obj else None), (normalize_role(role_obj.name) if role_obj else "viewer")


class UserCreateSchema(BaseModel):
    email: str
    full_name: str
    username: str | None = None
    password: str | None = None
    role_id: int | None = None
    group_ids: list[int] | None = []
    mfa_enabled: bool = False  # ignored: users enrol MFA themselves


class UserUpdateSchema(BaseModel):
    full_name: str | None = None
    email: str | None = None
    password: str | None = None
    role_id: int | None = None
    group_ids: list[int] | None = None
    is_active: bool | None = None
    mfa_enabled: bool | None = None  # only False (reset) is accepted


class GroupCreateSchema(BaseModel):
    name: str
    description: str | None = None


class GroupAssignSchema(BaseModel):
    user_ids: list[str]


class PolicyCreateSchema(BaseModel):
    name: str
    description: str | None = None
    user_id: str | None = None
    group_id: int | None = None
    finding_scope: dict[str, Any]


class SSOConfigSchema(BaseModel):
    provider: str
    client_id: str | None = None
    client_secret: str | None = None
    issuer_url: str | None = None
    metadata_url: str | None = None
    is_enabled: bool = False


class SignInPolicyUpdate(BaseModel):
    allow_local_login: bool | None = None
    captcha_enabled: bool | None = None


# ================= USER MANAGEMENT =================
@router.get("/users")
@router.get("/v1/users")
def list_users(db: Session = Depends(get_db)):
    seed_default_roles_if_empty(db)
    now = datetime.now(timezone.utc)
    active_sessions: dict[str, int] = {}
    for s in db.query(AuthSession).filter(AuthSession.is_active.is_(True)).all():
        active_sessions[s.user_id] = active_sessions.get(s.user_id, 0) + 1
    results = []
    for u in db.query(User).order_by(User.created_at.desc()).all():
        role_obj = db.get(Role, u.role_id) if u.role_id else None
        locked_until = u.locked_until if (u.locked_until is None or u.locked_until.tzinfo) else u.locked_until.replace(tzinfo=timezone.utc)
        results.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name or u.username,
            "username": u.username,
            "role_id": u.role_id,
            "role_name": role_obj.name if role_obj else (u.role or "Viewer"),
            "role": normalize_role(u.role),
            "auth_source": u.auth_source,
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "mfa_method": u.mfa_delivery_method if u.mfa_enabled else None,
            "failed_login_attempts": u.failed_login_attempts or 0,
            "locked": bool(locked_until and locked_until > now),
            "locked_until": locked_until.isoformat() if locked_until and locked_until > now else None,
            "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
            "last_login_ip": u.last_login_ip,
            "active_sessions": active_sessions.get(u.id, 0),
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "groups": [g.name for g in u.groups_rel] if hasattr(u, "groups_rel") else [],
            "group_ids": [g.id for g in u.groups_rel] if hasattr(u, "groups_rel") else [],
        })
    return results


@router.post("/users")
@router.post("/v1/users")
def create_user(payload: UserCreateSchema, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    seed_default_roles_if_empty(db)
    email = payload.email.strip().lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists.")
    uname = (payload.username or email.split("@")[0]).strip()
    if db.query(User).filter(User.username == uname).first():
        raise HTTPException(status_code=400, detail="That username is taken.")

    temporary_password = None
    if payload.password:
        _check_password(payload.password)
        pwd_hash = hash_password(payload.password)
    else:
        temporary_password = secrets.token_urlsafe(14)
        pwd_hash = hash_password(temporary_password)
    role_id, role = _role_for(db, payload.role_id)

    user = User(email=email, full_name=payload.full_name.strip(), username=uname, password_hash=pwd_hash,
                role_id=role_id, role=role, mfa_enabled=False, mfa_secret=None, is_active=True)
    if payload.group_ids:
        user.groups_rel = db.query(Group).filter(Group.id.in_(payload.group_ids)).all()
    db.add(user)
    db.flush()
    _audit(db, actor, "user.create", user, {"role": role})
    db.commit()
    response = {"message": "User created.", "user_id": user.id}
    if temporary_password:
        response["temporary_password"] = temporary_password
    return response


@router.put("/users/{user_id}")
@router.put("/v1/users/{user_id}")
def update_user(user_id: str, payload: UserUpdateSchema, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    changes: dict[str, Any] = {}

    if payload.role_id is not None:
        role_id, role = _role_for(db, payload.role_id)
        if role != "admin":
            _guard_admin_change(db, actor, user, removes_admin=_is_admin(user), action="demote")
        if role != normalize_role(user.role):
            changes["role"] = [normalize_role(user.role), role]
        user.role_id, user.role = role_id, role
    if payload.is_active is False and user.is_active:
        _guard_admin_change(db, actor, user, removes_admin=True, action="deactivate")
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.email is not None and payload.email.strip().lower() != user.email:
        email = payload.email.strip().lower()
        if not _EMAIL_RE.match(email):
            raise HTTPException(status_code=400, detail="Enter a valid email address.")
        if db.query(User).filter(User.email == email, User.id != user.id).first():
            raise HTTPException(status_code=400, detail="Another user already has that email.")
        changes["email"] = [user.email, email]
        user.email = email
    if payload.password and payload.password.strip():
        _check_password(payload.password.strip())
        user.password_hash = hash_password(payload.password.strip())
        changes["password"] = "reset"
        changes["sessions_revoked"] = _revoke_sessions(db, user)
    if payload.group_ids is not None:
        user.groups_rel = db.query(Group).filter(Group.id.in_(payload.group_ids)).all()
        changes["groups"] = [g.name for g in user.groups_rel]
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        changes["active"] = payload.is_active
        if not payload.is_active:
            changes["sessions_revoked"] = _revoke_sessions(db, user)
    if payload.mfa_enabled is True and not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Users turn MFA on themselves from their profile, so they receive the secret. You can only reset it here.")
    if payload.mfa_enabled is False and user.mfa_enabled:
        user.mfa_enabled, user.mfa_secret = False, None
        changes["mfa"] = "reset"
    _audit(db, actor, "user.update", user, changes)
    db.commit()
    return {"message": "User updated."}


@router.delete("/users/{user_id}")
@router.delete("/v1/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    _guard_admin_change(db, actor, user, removes_admin=True, action="delete")
    _audit(db, actor, "user.delete", user, {"email": user.email, "role": normalize_role(user.role)})
    user.groups_rel = []
    db.query(AuthSession).filter(AuthSession.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"message": "User deleted."}


@router.post("/users/{user_id}/toggle-active")
@router.post("/v1/users/{user_id}/toggle-active")
def toggle_user_active(user_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_active:
        _guard_admin_change(db, actor, user, removes_admin=True, action="deactivate")
    user.is_active = not user.is_active
    revoked = 0 if user.is_active else _revoke_sessions(db, user)
    _audit(db, actor, "user.activate" if user.is_active else "user.deactivate", user, {"sessions_revoked": revoked})
    db.commit()
    return {"message": f"User {'activated' if user.is_active else 'deactivated'}.", "is_active": user.is_active}


@router.post("/users/{user_id}/toggle-mfa")
@router.post("/v1/users/{user_id}/toggle-mfa")
def reset_user_mfa(user_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    """Reset a user's MFA (e.g. lost phone). Turning MFA on is done by the user, who must receive the secret."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="This user hasn't set up MFA. They enable it themselves from their profile.")
    user.mfa_enabled, user.mfa_secret = False, None
    user.email_mfa_code, user.email_mfa_expires_at = None, None
    _audit(db, actor, "user.mfa_reset", user, {})
    db.commit()
    return {"message": "MFA reset. The user will be asked to set it up again.", "mfa_enabled": False}


@router.post("/users/{user_id}/unlock")
@router.post("/v1/users/{user_id}/unlock")
def unlock_user(user_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    before = user.failed_login_attempts
    user.failed_login_attempts, user.locked_until = 0, None
    _audit(db, actor, "user.unlock", user, {"failed_attempts_cleared": before})
    db.commit()
    return {"message": "Account unlocked."}


@router.get("/users/{user_id}/sessions")
@router.get("/v1/users/{user_id}/sessions")
def list_user_sessions(user_id: str, db: Session = Depends(get_db)):
    if not db.get(User, user_id):
        raise HTTPException(status_code=404, detail="User not found")
    rows = db.query(AuthSession).filter(AuthSession.user_id == user_id).order_by(AuthSession.last_seen_at.desc()).limit(20).all()
    return [{"id": str(s.id), "ip_address": s.ip_address, "user_agent": s.user_agent, "device_name": s.device_name,
             "is_active": s.is_active, "created_at": s.created_at.isoformat() if s.created_at else None,
             "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None} for s in rows]


@router.post("/users/{user_id}/revoke-sessions")
@router.post("/v1/users/{user_id}/revoke-sessions")
def revoke_user_sessions(user_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    count = _revoke_sessions(db, user)
    _audit(db, actor, "user.sessions_revoked", user, {"count": count})
    db.commit()
    note = " That includes your current session, so you'll need to sign in again." if user.id == actor.id else ""
    return {"message": f"Signed out of {count} session{'s' if count != 1 else ''}.{note}", "revoked": count}


@router.get("/audit")
@router.get("/v1/audit")
def recent_access_audit(db: Session = Depends(get_db)):
    """Recent sign-in and access-management events."""
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.resource_type.in_(["user", "auth", "session"]) | AuditLog.action.like("auth.%") | AuditLog.action.like("user.%"))
        .order_by(AuditLog.created_at.desc())
        .limit(40)
        .all()
    )
    return [{"id": str(r.id), "actor": r.actor, "action": r.action, "outcome": r.outcome, "resource_id": r.resource_id,
             "details": r.details, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]


# ================= SIGN-IN POLICY & SSO (the settings sign-in actually enforces) =================
@router.get("/sign-in")
@router.get("/v1/sign-in")
def sign_in_settings(db: Session = Depends(get_db)):
    policy = db.query(AuthPolicy).filter(AuthPolicy.policy_name == "default").first()
    providers = db.query(SSOProvider).order_by(SSOProvider.created_at.desc()).all()
    return {
        "allow_local_login": policy.allow_local_login if policy else True,
        "captcha_enabled": policy.captcha_enabled if policy else False,
        "access_code_configured": access_code_configured(),
        "access_code_enforced": access_code_required(policy),
        "providers": [{"id": str(p.id), "name": p.name, "type": p.provider_type, "login_url": p.login_url,
                       "client_id_set": bool(p.client_id), "secret_set": bool(p.client_secret), "enabled": p.enabled,
                       "placeholder": ".example." in (p.login_url or "") or (p.login_url or "").endswith(".local") or ".local/" in (p.login_url or "")}
                      for p in providers],
    }


@router.post("/sign-in")
@router.post("/v1/sign-in")
def update_sign_in_settings(payload: SignInPolicyUpdate, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    policy = db.query(AuthPolicy).filter(AuthPolicy.policy_name == "default").first()
    if not policy:
        policy = AuthPolicy(policy_name="default")
        db.add(policy)
    if payload.allow_local_login is False:
        if not db.query(SSOProvider).filter(SSOProvider.enabled.is_(True)).count():
            raise HTTPException(status_code=400, detail="Enable a working SSO provider before turning off password sign-in, or nobody can sign in.")
    if payload.captcha_enabled and not access_code_configured():
        raise HTTPException(status_code=400, detail="Set CAPTCHA_BYPASS_TOKEN to a private code in the API's environment first. Until then there is no code to ask for.")
    before = {"allow_local_login": policy.allow_local_login, "captcha_enabled": policy.captcha_enabled}
    if payload.allow_local_login is not None:
        policy.allow_local_login = payload.allow_local_login
    if payload.captcha_enabled is not None:
        policy.captcha_enabled = payload.captcha_enabled
    db.add(AuditLog(actor=actor.username, action="auth.policy_update", resource_type="auth", resource_id="default",
                    details={"before": before, "after": {"allow_local_login": policy.allow_local_login, "captcha_enabled": policy.captcha_enabled}}))
    db.commit()
    return {"allow_local_login": policy.allow_local_login, "captcha_enabled": policy.captcha_enabled,
            "access_code_enforced": access_code_required(policy)}


@router.post("/sso-providers/{provider_id}/toggle")
@router.post("/v1/sso-providers/{provider_id}/toggle")
def toggle_sso_provider(provider_id: str, db: Session = Depends(get_db), actor: User = Depends(get_current_user)):
    import uuid

    try:
        provider = db.get(SSOProvider, uuid.UUID(provider_id))
    except ValueError:
        provider = None
    if not provider:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    provider.enabled = not provider.enabled
    db.add(AuditLog(actor=actor.username, action="auth.sso_toggle", resource_type="auth", resource_id=str(provider.id),
                    details={"name": provider.name, "enabled": provider.enabled}))
    db.commit()
    return {"id": str(provider.id), "enabled": provider.enabled}


# ================= GROUP MANAGEMENT =================
@router.get("/groups")
@router.get("/v1/groups")
def list_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).order_by(Group.created_at.desc()).all()
    return [{
        "id": g.id,
        "name": g.name,
        "description": g.description,
        "user_count": len(g.users),
        "users": [{"id": u.id, "email": u.email, "full_name": u.full_name or u.username} for u in g.users],
        "created_at": g.created_at.isoformat() if g.created_at else None,
    } for g in groups]


@router.post("/groups")
@router.post("/v1/groups")
def create_group(payload: GroupCreateSchema, db: Session = Depends(get_db)):
    if db.query(Group).filter(Group.name == payload.name.strip()).first():
        raise HTTPException(status_code=400, detail="Group with this name already exists")
    g = Group(name=payload.name.strip(), description=payload.description)
    db.add(g)
    db.commit()
    db.refresh(g)
    return {"message": "Group created successfully", "group_id": g.id}


@router.put("/groups/{group_id}")
@router.put("/v1/groups/{group_id}")
def update_group(group_id: int, payload: GroupCreateSchema, db: Session = Depends(get_db)):
    g = db.get(Group, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    g.name = payload.name.strip()
    g.description = payload.description
    db.commit()
    return {"message": "Group updated successfully"}


@router.delete("/groups/{group_id}")
@router.delete("/v1/groups/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db)):
    g = db.get(Group, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    db.delete(g)
    db.commit()
    return {"message": "Group deleted successfully"}


@router.post("/groups/{group_id}/assign-users")
@router.post("/v1/groups/{group_id}/assign-users")
def assign_group_users(group_id: int, payload: GroupAssignSchema, db: Session = Depends(get_db)):
    g = db.get(Group, group_id)
    if not g:
        raise HTTPException(status_code=404, detail="Group not found")
    g.users = db.query(User).filter(User.id.in_(payload.user_ids)).all()
    db.commit()
    return {"message": f"Assigned {len(g.users)} users to group {g.name}"}


# ================= ROLES =================
@router.get("/roles")
@router.get("/v1/roles")
def list_roles(db: Session = Depends(get_db)):
    seed_default_roles_if_empty(db)
    return [{"id": r.id, "name": r.name, "description": r.description, "permissions": r.permissions,
             "platform_role": normalize_role(r.name)} for r in db.query(Role).all()]


# ================= LEGACY (not enforced anywhere; kept for API compatibility) =================
@router.get("/policies")
@router.get("/v1/policies")
def list_policies(db: Session = Depends(get_db)):
    return [{"id": p.id, "name": p.name, "description": p.description, "user_id": p.user_id, "group_id": p.group_id,
             "finding_scope": p.finding_scope, "enforced": False,
             "created_at": p.created_at.isoformat() if p.created_at else None}
            for p in db.query(Policy).order_by(Policy.created_at.desc()).all()]


@router.post("/policies")
@router.post("/v1/policies")
def create_policy(payload: PolicyCreateSchema, db: Session = Depends(get_db)):
    raise HTTPException(status_code=410, detail="Finding-scope policies were never enforced and have been retired. Use roles and groups.")


@router.delete("/policies/{policy_id}")
@router.delete("/v1/policies/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    p = db.get(Policy, policy_id)
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(p)
    db.commit()
    return {"message": "Policy deleted successfully"}


@router.get("/sso")
@router.get("/v1/sso")
def list_sso_configs(db: Session = Depends(get_db)):
    """Legacy SSO settings (sign-in uses /iam/sign-in providers). Secrets are never returned."""
    configs = {c.provider: c for c in db.query(SSOConfig).all()}
    return [{"id": c.id if c else None, "provider": p, "client_id": c.client_id if c else "",
             "client_secret_set": bool(c and c.client_secret), "issuer_url": c.issuer_url if c else "",
             "metadata_url": c.metadata_url if c else "", "is_enabled": c.is_enabled if c else False, "enforced": False,
             "updated_at": c.updated_at.isoformat() if c and c.updated_at else None}
            for p, c in ((p, configs.get(p)) for p in ["google", "okta", "azure", "github"])]


@router.post("/sso")
@router.post("/v1/sso")
def save_sso_config(payload: SSOConfigSchema, db: Session = Depends(get_db)):
    raise HTTPException(status_code=410, detail="These SSO settings were never used by sign-in. Configure SSO providers under /iam/sign-in.")
