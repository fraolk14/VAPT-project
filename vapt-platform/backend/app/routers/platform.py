from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.platform import DevSecOpsEvent, DevSecOpsHook, PluginRegistration, PublicApiKey
from app.models.user import User
from app.schemas.platform import (
    ApiKeyCreate,
    ApiKeyCreateResponse,
    ApiKeyResponse,
    AttackPathSummary,
    AttackSurfaceSummary,
    DevSecOpsEventResponse,
    DevSecOpsHookCreate,
    DevSecOpsHookCreateResponse,
    DevSecOpsHookResponse,
    PluginCreate,
    PluginResponse,
)
from app.services.platform import (
    create_api_key,
    create_devsecops_hook,
    record_devsecops_event,
    summarize_attack_paths,
    summarize_attack_surface,
    verify_hook_secret,
)
from app.services.security import enforce_roles, get_current_user

router = APIRouter(prefix="/platform", tags=["Platform"])


@router.get("/plugins", response_model=list[PluginResponse])
def list_plugins(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(PluginRegistration).order_by(PluginRegistration.created_at.desc()).all()


@router.post("/plugins", response_model=PluginResponse)
def register_plugin(
    payload: PluginCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    plugin = PluginRegistration(
        name=payload.name,
        plugin_type=payload.plugin_type,
        version=payload.version,
        entrypoint=payload.entrypoint,
        capabilities=payload.capabilities,
        config=payload.config,
        enabled=True,
    )
    db.add(plugin)
    db.commit()
    db.refresh(plugin)
    return plugin


@router.post("/plugins/{plugin_id}/toggle", response_model=PluginResponse)
def toggle_plugin(plugin_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    plugin = db.get(PluginRegistration, plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    plugin.enabled = not plugin.enabled
    db.commit()
    db.refresh(plugin)
    return plugin


@router.get("/api-keys", response_model=list[ApiKeyResponse])
def list_api_keys(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    return db.query(PublicApiKey).order_by(PublicApiKey.created_at.desc()).all()


@router.post("/api-keys", response_model=ApiKeyCreateResponse)
def create_public_api_key(
    payload: ApiKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    key, secret = create_api_key(db, payload.name, payload.role_scope)
    return ApiKeyCreateResponse.model_validate({**key.__dict__, "secret": secret})


@router.post("/api-keys/{key_id}/toggle", response_model=ApiKeyResponse)
def toggle_api_key(key_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    key = db.get(PublicApiKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.enabled = not key.enabled
    db.commit()
    db.refresh(key)
    return key


@router.get("/devsecops/hooks", response_model=list[DevSecOpsHookResponse])
def list_hooks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(DevSecOpsHook).order_by(DevSecOpsHook.created_at.desc()).all()


@router.post("/devsecops/hooks", response_model=DevSecOpsHookCreateResponse)
def create_hook(
    payload: DevSecOpsHookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    enforce_roles(current_user, "admin")
    hook, secret = create_devsecops_hook(
        db=db,
        name=payload.name,
        provider=payload.provider,
        project_name=payload.project_name,
        target_url=payload.target_url,
        metadata_json=payload.metadata_json,
    )
    return DevSecOpsHookCreateResponse.model_validate({**hook.__dict__, "secret": secret})


@router.post("/devsecops/hooks/{hook_id}/toggle", response_model=DevSecOpsHookResponse)
def toggle_hook(hook_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin")
    hook = db.get(DevSecOpsHook, hook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Hook not found")
    hook.enabled = not hook.enabled
    db.commit()
    db.refresh(hook)
    return hook


@router.get("/devsecops/events", response_model=list[DevSecOpsEventResponse])
def list_devsecops_events(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst")
    return db.query(DevSecOpsEvent).order_by(DevSecOpsEvent.created_at.desc()).limit(50).all()


@router.post("/devsecops/ingest/{hook_id}", response_model=DevSecOpsEventResponse)
async def ingest_devsecops_event(
    hook_id: str,
    request: Request,
    x_hook_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    hook = db.get(DevSecOpsHook, hook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Hook not found")
    if not verify_hook_secret(hook, x_hook_token):
        raise HTTPException(status_code=401, detail="Invalid hook token")
    payload = await request.json()
    return record_devsecops_event(db, hook, payload)


@router.get("/attack-surface/summary", response_model=AttackSurfaceSummary)
def get_attack_surface_summary(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    return summarize_attack_surface(db)


@router.get("/attack-surface/paths", response_model=AttackPathSummary)
def get_attack_paths(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enforce_roles(current_user, "admin", "analyst", "viewer")
    return summarize_attack_paths(db)
