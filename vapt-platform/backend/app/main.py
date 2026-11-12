import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, get_db
from app.models import ai, alert, asset, auth, finding, operations, platform, scan, schedule, tenant, user, vulnerability
from app.routers import agent as agent_router
from app.routers import ai as ai_router
from app.routers import alerts as alerts_router
from app.routers import asset as asset_router
from app.routers import auth as auth_router
from app.routers import dashboard as dashboard_router
from app.routers import finding as finding_router
from app.routers import iam as iam_router
from app.routers import integrations as integrations_router
from app.routers import misconfiguration as misconfiguration_router
from app.routers import operations as operations_router
from app.routers import platform as platform_router
from app.routers import posture as posture_router
from app.routers import reports as reports_router
from app.routers import scan as scan_router
from app.routers import schedule as schedule_router
from app.routers import shadow_it as shadow_it_router
from app.routers import software as software_router
from app.routers import threat_intelligence as threat_intelligence_router
from app.routers import vulnerability as vulnerability_router
from app.services.bootstrap import ensure_runtime_schema
from app.services.demo_seed import seed_demo_data
from app.services.orchestrator import resume_inflight_scans
from app.services.scheduler import start_scheduler
from app.services.security import get_current_user, require_admin

Base.metadata.create_all(bind=engine)

ENABLE_API_DOCS = os.getenv("ENABLE_API_DOCS", "false").lower() == "true"

app = FastAPI(
    title="VAPT Platform API",
    version="1.0.0",
    description="Unified VAPT orchestration platform for network, web, mobile, and shadow IT assessments.",
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
)


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ALLOW_ORIGINS", "")
    origins = [o.strip().rstrip("/") for o in configured.split(",") if o.strip()]
    frontend = os.getenv("FRONTEND_BASE_URL", "").strip().rstrip("/")
    if frontend:
        origins.append(frontend)
    origins += ["http://localhost:18080", "http://127.0.0.1:18080"]
    return sorted(set(origins))


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,  # the UI authenticates with a bearer header, not cookies
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every router below requires a signed-in user. Finer role checks live inside the routers.
# Exceptions: `auth` (login/MFA/SSO must be reachable signed-out) and `agent` (endpoint
# agents authenticate with their own enrollment token / per-device key).
SIGNED_IN = [Depends(get_current_user)]
ADMIN_ONLY = [Depends(require_admin)]

PREFIXES_ALL = ("", "/api", "/api/v1")

app.include_router(auth_router.router)
for _prefix in PREFIXES_ALL:
    app.include_router(agent_router.router, prefix=_prefix)
    app.include_router(asset_router.router, prefix=_prefix, dependencies=SIGNED_IN)
    app.include_router(scan_router.router, prefix=_prefix, dependencies=SIGNED_IN)
    app.include_router(threat_intelligence_router.router, prefix=_prefix, dependencies=SIGNED_IN)
    app.include_router(iam_router.router, prefix=_prefix, dependencies=ADMIN_ONLY)
    app.include_router(software_router.router, prefix=_prefix, dependencies=SIGNED_IN)

for _router in (
    ai_router,
    finding_router,
    dashboard_router,
    reports_router,
    integrations_router,
    shadow_it_router,
    misconfiguration_router,
    vulnerability_router,
    posture_router,
    schedule_router,
    alerts_router,
    platform_router,
    operations_router,
):
    app.include_router(_router.router, dependencies=SIGNED_IN)


@app.get("/api/v1/attack-map/data", dependencies=SIGNED_IN)
@app.get("/attack-map/data", dependencies=SIGNED_IN)
def get_attack_map_dashboard_root(time_range: str = "24h", db: Session = Depends(get_db)):
    from app.services.threat_intelligence import build_attack_map_dashboard_data

    return build_attack_map_dashboard_data(db, time_range=time_range)


@app.on_event("startup")
def startup() -> None:
    ensure_runtime_schema()
    start_scheduler()
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    resume_inflight_scans()


@app.get("/health")
def health():
    return {"status": "ok", "service": "vapt-platform-api"}
