from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.hosts import build_hosts

router = APIRouter(prefix="/hosts", tags=["Hosts"])


@router.get("/overview")
def hosts_overview(db: Session = Depends(get_db)):
    """Per-host scan coverage, freshness and open findings."""
    return build_hosts(db)
