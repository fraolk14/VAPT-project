from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, SessionLocal, engine
from app.models import asset, finding, scan, user, vulnerability
from app.routers import asset as asset_router
from app.routers import auth as auth_router
from app.routers import dashboard as dashboard_router
from app.routers import finding as finding_router
from app.routers import integrations as integrations_router
from app.routers import reports as reports_router
from app.routers import scan as scan_router
from app.services.demo_seed import seed_demo_data

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
app.include_router(asset_router.router)
app.include_router(scan_router.router)
app.include_router(finding_router.router)
app.include_router(dashboard_router.router)
app.include_router(reports_router.router)
app.include_router(integrations_router.router)


@app.on_event("startup")
def startup() -> None:
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()


@app.get("/health")
def health():
    return {"status": "ok", "service": "vapt-platform-api"}
