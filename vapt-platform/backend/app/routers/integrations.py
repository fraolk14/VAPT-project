from fastapi import APIRouter

from app.services.integrations import integration_health

router = APIRouter(prefix="/integrations", tags=["Integrations"])


@router.get("/health")
def read_integrations_health():
    return integration_health()


@router.get("/feeds")
def read_threat_feed_status():
    """Live reachability of the threat-intel feeds (probed, cached 5 minutes) and which need API keys."""
    from app.services.intel import sources_status

    return sources_status()
