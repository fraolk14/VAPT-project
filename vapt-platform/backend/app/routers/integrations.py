from fastapi import APIRouter

from app.services.integrations import integration_health

router = APIRouter(prefix="/integrations", tags=["Integrations"])


@router.get("/health")
def read_integrations_health():
    return integration_health()
