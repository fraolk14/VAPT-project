from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, SessionLocal, engine
from app.models import ai, alert, asset, auth, finding, operations, platform, scan, schedule, tenant, user, vulnerability
from app.routers import asset as asset_router
from app.routers import ai as ai_router
from app.routers import auth as auth_router
from app.routers import dashboard as dashboard_router
from app.routers import finding as finding_router
from app.routers import integrations as integrations_router
from app.routers import posture as posture_router
from app.routers import platform as platform_router
from app.routers import operations as operations_router
from app.routers import reports as reports_router
from app.routers import alerts as alerts_router
from app.routers import schedule as schedule_router
from app.routers import scan as scan_router
from app.routers import threat_intelligence as threat_intelligence_router
from app.routers import vulnerability as vulnerability_router
from app.services.bootstrap import ensure_runtime_schema
from app.services.demo_seed import seed_demo_data
from app.services.scheduler import start_scheduler

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VAPT Platform API",
    version="1.0.0",
    description="Unified VAPT orchestration platform for network, web, mobile, and shadow IT assessments.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(ai_router.router)
app.include_router(asset_router.router)
app.include_router(scan_router.router)
app.include_router(finding_router.router)
app.include_router(dashboard_router.router)
app.include_router(reports_router.router)
app.include_router(integrations_router.router)
app.include_router(threat_intelligence_router.router)
app.include_router(vulnerability_router.router)
app.include_router(posture_router.router)
app.include_router(schedule_router.router)
app.include_router(alerts_router.router)
app.include_router(platform_router.router)
app.include_router(operations_router.router)


@app.on_event("startup")
def startup() -> None:
    ensure_runtime_schema()
    start_scheduler()
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok", "service": "vapt-platform-api"}
