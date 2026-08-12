from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.posture import discover_shadow_it_for_org

router = APIRouter(tags=["Shadow IT Discovery"])


@router.get("/shadow-it/discover/{organization:path}")
@router.get("/v1/shadow-it/discover/{organization:path}")
def discover_shadow_it(organization: str, db: Session = Depends(get_db)):
    return discover_shadow_it_for_org(db, organization)
