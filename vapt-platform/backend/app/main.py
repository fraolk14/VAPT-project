from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, get_db
from app.models import ai, alert, asset, auth, finding, operations, platform, scan, schedule, tenant, user, vulnerability
from app.routers import asset as asset_router
from app.routers import ai as ai_router
from app.routers import auth as auth_router
from app.routers import dashboard as dashboard_router
from app.routers import finding as finding_router
from app.routers import integrations as integrations_router
from app.routers import iam as iam_router
from app.routers import misconfiguration as misconfiguration_router
from app.routers import agent as agent_router
from app.routers import posture as posture_router
from app.routers import platform as platform_router
from app.routers import operations as operations_router
from app.routers import reports as reports_router
from app.routers import alerts as alerts_router
from app.routers import schedule as schedule_router
from app.routers import scan as scan_router
from app.routers import shadow_it as shadow_it_router
from app.routers import software as software_router
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
app.include_router(asset_router.router, prefix="/api")
app.include_router(asset_router.router, prefix="/api/v1")
app.include_router(scan_router.router)
app.include_router(scan_router.router, prefix="/api")
app.include_router(scan_router.router, prefix="/api/v1")
app.include_router(finding_router.router)
app.include_router(dashboard_router.router)
app.include_router(reports_router.router)
app.include_router(integrations_router.router)
app.include_router(threat_intelligence_router.router)
app.include_router(threat_intelligence_router.router, prefix="/api")
app.include_router(threat_intelligence_router.router, prefix="/api/v1")


@app.get("/api/v1/attack-map/data")
@app.get("/attack-map/data")
def get_attack_map_dashboard_root(time_range: str = "24h", db: Session = Depends(get_db)):
    from app.services.threat_intelligence import build_attack_map_dashboard_data
    return build_attack_map_dashboard_data(db, time_range=time_range)
app.include_router(shadow_it_router.router)
app.include_router(misconfiguration_router.router)
app.include_router(iam_router.router)
app.include_router(iam_router.router, prefix="/api")
app.include_router(iam_router.router, prefix="/api/v1")
app.include_router(vulnerability_router.router)
app.include_router(posture_router.router)
app.include_router(schedule_router.router)
app.include_router(alerts_router.router)
app.include_router(platform_router.router)
app.include_router(operations_router.router)
app.include_router(software_router.router)
app.include_router(software_router.router, prefix="/api")
app.include_router(software_router.router, prefix="/api/v1")
app.include_router(agent_router.router)
app.include_router(agent_router.router, prefix="/api")
app.include_router(agent_router.router, prefix="/api/v1")


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
