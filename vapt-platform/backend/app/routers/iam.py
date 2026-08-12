import pyotp
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.auth import AuthSession
from app.models.iam import Group, Policy, Role, SSOConfig
from app.models.user import User
from app.services.security import hash_password

router = APIRouter(prefix="/iam", tags=["Identity & Access Management Engine"])


# Default Roles Seeding Helper
def seed_default_roles_if_empty(db: Session):
    if db.query(Role).count() == 0:
        default_roles = [
            {
                "name": "Admin",
                "description": "Full platform administrative access to manage users, security scans, and platform settings.",
                "permissions": {"view_findings": True, "edit_findings": True, "manage_users": True, "view_reports": True, "run_scans": True},
            },
            {
                "name": "SecurityEngineer",
                "description": "Access to trigger scans, remediate misconfigurations, and configure security rules.",
                "permissions": {"view_findings": True, "edit_findings": True, "manage_users": False, "view_reports": True, "run_scans": True},
            },
            {
                "name": "Auditor",
                "description": "Read-only compliance audit access to view posture, reports, and evidence.",
                "permissions": {"view_findings": True, "edit_findings": False, "manage_users": False, "view_reports": True, "run_scans": False},
            },
            {
                "name": "Viewer",
                "description": "Restricted view access to high-level posture metrics.",
                "permissions": {"view_findings": True, "edit_findings": False, "manage_users": False, "view_reports": False, "run_scans": False},
            },
        ]
        for r in default_roles:
            db.add(Role(name=r["name"], description=r["description"], permissions=r["permissions"]))
        db.commit()


# Pydantic Schemas
class UserCreateSchema(BaseModel):
    email: str
    full_name: str
    username: str | None = None
    password: str | None = "ChangeMe123!"
    role_id: int | None = None
    group_ids: list[int] | None = []
    mfa_enabled: bool = False


class UserUpdateSchema(BaseModel):
    full_name: str | None = None
    email: str | None = None
    password: str | None = None
    role_id: int | None = None
    group_ids: list[int] | None = None
    is_active: bool | None = None
    mfa_enabled: bool | None = None


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
    finding_scope: dict[str, Any]  # {"asset_types": [...], "severities": [...], "cves": [...]}


class SSOConfigSchema(BaseModel):
    provider: str  # "google", "okta", "azure", "github"
    client_id: str | None = None
    client_secret: str | None = None
    issuer_url: str | None = None
    metadata_url: str | None = None
    is_enabled: bool = False


# ================= USER MANAGEMENT =================
@router.get("/users")
@router.get("/v1/users")
def list_users(db: Session = Depends(get_db)):
    seed_default_roles_if_empty(db)
    users = db.query(User).order_by(User.created_at.desc()).all()
    results = []
    for u in users:
        role_obj = db.get(Role, u.role_id) if u.role_id else None
        results.append({
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name or u.username,
            "username": u.username,
            "role_id": u.role_id,
            "role_name": role_obj.name if role_obj else (u.role or "Viewer"),
            "is_active": u.is_active,
            "mfa_enabled": u.mfa_enabled,
            "last_login": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "groups": [g.name for g in u.groups_rel] if hasattr(u, "groups_rel") else [],
            "group_ids": [g.id for g in u.groups_rel] if hasattr(u, "groups_rel") else [],
        })
    return results


@router.post("/users")
@router.post("/v1/users")
def create_user(payload: UserCreateSchema, db: Session = Depends(get_db)):
    seed_default_roles_if_empty(db)
    existing = db.query(User).filter(User.email == payload.email.strip()).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    uname = payload.username or payload.email.split("@")[0]
    pwd_hash = hash_password(payload.password or "Pass@123456")
    mfa_secret = pyotp.random_base32() if payload.mfa_enabled else None

    user = User(
        email=payload.email.strip(),
        full_name=payload.full_name.strip(),
        username=uname,
        password_hash=pwd_hash,
        role_id=payload.role_id,
        role=db.get(Role, payload.role_id).name if payload.role_id and db.get(Role, payload.role_id) else "viewer",
        mfa_enabled=payload.mfa_enabled,
        mfa_secret=mfa_secret,
        is_active=True,
    )
    if payload.group_ids:
        group_objs = db.query(Group).filter(Group.id.in_(payload.group_ids)).all()
        user.groups_rel = group_objs

    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User created successfully", "user_id": user.id}


@router.put("/users/{user_id}")
@router.put("/v1/users/{user_id}")
def update_user(user_id: str, payload: UserUpdateSchema, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.email is not None:
        user.email = payload.email
    if payload.password and payload.password.strip():
        user.password_hash = hash_password(payload.password.strip())
    if payload.role_id is not None:
        user.role_id = payload.role_id
        r_obj = db.get(Role, payload.role_id)
        if r_obj:
            user.role = r_obj.name
    if payload.group_ids is not None:
        group_objs = db.query(Group).filter(Group.id.in_(payload.group_ids)).all()
        user.groups_rel = group_objs
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.mfa_enabled is not None:
        user.mfa_enabled = payload.mfa_enabled
        if payload.mfa_enabled and not user.mfa_secret:
            user.mfa_secret = pyotp.random_base32()

    db.commit()
    return {"message": "User updated successfully"}


@router.delete("/users/{user_id}")
@router.delete("/v1/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == "admin" or user.email == "admin@vapt.local":
        raise HTTPException(status_code=400, detail="Primary system administrator account cannot be deleted.")

    user.groups_rel = []
    db.query(AuthSession).filter(AuthSession.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}


@router.post("/users/{user_id}/toggle-active")
@router.post("/v1/users/{user_id}/toggle-active")
def toggle_user_active(user_id: str, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = not user.is_active
    db.commit()
    return {"message": f"User status changed to {'active' if user.is_active else 'inactive'}", "is_active": user.is_active}


@router.post("/users/{user_id}/toggle-mfa")
@router.post("/v1/users/{user_id}/toggle-mfa")
def toggle_user_mfa(user_id: str, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.mfa_enabled = not user.mfa_enabled
    if user.mfa_enabled and not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
    db.commit()
    return {"message": f"MFA status changed to {'enabled' if user.mfa_enabled else 'disabled'}", "mfa_enabled": user.mfa_enabled}


# ================= GROUP MANAGEMENT =================
@router.get("/groups")
@router.get("/v1/groups")
def list_groups(db: Session = Depends(get_db)):
    groups = db.query(Group).order_by(Group.created_at.desc()).all()
    results = []
    for g in groups:
        results.append({
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "user_count": len(g.users),
            "users": [{"id": u.id, "email": u.email, "full_name": u.full_name or u.username} for u in g.users],
            "created_at": g.created_at.isoformat() if g.created_at else None,
        })
    return results


@router.post("/groups")
@router.post("/v1/groups")
def create_group(payload: GroupCreateSchema, db: Session = Depends(get_db)):
    existing = db.query(Group).filter(Group.name == payload.name.strip()).first()
    if existing:
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
    users = db.query(User).filter(User.id.in_(payload.user_ids)).all()
    g.users = users
    db.commit()
    return {"message": f"Assigned {len(users)} users to group {g.name}"}


# ================= ROLES & RBAC =================
@router.get("/roles")
@router.get("/v1/roles")
def list_roles(db: Session = Depends(get_db)):
    seed_default_roles_if_empty(db)
    roles = db.query(Role).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "permissions": r.permissions,
        }
        for r in roles
    ]


# ================= POLICY ENGINE =================
@router.get("/policies")
@router.get("/v1/policies")
def list_policies(db: Session = Depends(get_db)):
    policies = db.query(Policy).order_by(Policy.created_at.desc()).all()
    results = []
    for p in policies:
        user_obj = db.get(User, p.user_id) if p.user_id else None
        group_obj = db.get(Group, p.group_id) if p.group_id else None
        results.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "user_id": p.user_id,
            "user_name": user_obj.full_name or user_obj.email if user_obj else None,
            "group_id": p.group_id,
            "group_name": group_obj.name if group_obj else None,
            "finding_scope": p.finding_scope,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })
    return results


@router.post("/policies")
@router.post("/v1/policies")
def create_policy(payload: PolicyCreateSchema, db: Session = Depends(get_db)):
    p = Policy(
        name=payload.name.strip(),
        description=payload.description,
        user_id=payload.user_id,
        group_id=payload.group_id,
        finding_scope=payload.finding_scope,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return {"message": "Policy created successfully", "policy_id": p.id}


@router.delete("/policies/{policy_id}")
@router.delete("/v1/policies/{policy_id}")
def delete_policy(policy_id: int, db: Session = Depends(get_db)):
    p = db.get(Policy, policy_id)
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    db.delete(p)
    db.commit()
    return {"message": "Policy deleted successfully"}


# ================= SSO CONFIGURATION =================
@router.get("/sso")
@router.get("/v1/sso")
def list_sso_configs(db: Session = Depends(get_db)):
    providers = ["google", "okta", "azure", "github"]
    configs = {c.provider: c for c in db.query(SSOConfig).all()}

    results = []
    for p in providers:
        c = configs.get(p)
        results.append({
            "id": c.id if c else None,
            "provider": p,
            "client_id": c.client_id if c else "",
            "client_secret": c.client_secret if c else "",
            "issuer_url": c.issuer_url if c else "",
            "metadata_url": c.metadata_url if c else "",
            "is_enabled": c.is_enabled if c else False,
            "updated_at": c.updated_at.isoformat() if c and c.updated_at else None,
        })
    return results


@router.post("/sso")
@router.post("/v1/sso")
def save_sso_config(payload: SSOConfigSchema, db: Session = Depends(get_db)):
    c = db.query(SSOConfig).filter(SSOConfig.provider == payload.provider.strip().lower()).first()
    if not c:
        c = SSOConfig(provider=payload.provider.strip().lower())
        db.add(c)

    c.client_id = payload.client_id
    c.client_secret = payload.client_secret
    c.issuer_url = payload.issuer_url
    c.metadata_url = payload.metadata_url
    c.is_enabled = payload.is_enabled
    c.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": f"SSO configuration for {payload.provider} saved successfully", "is_enabled": c.is_enabled}
