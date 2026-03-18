from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.risk import Risk

router = APIRouter(
    prefix="/risks",
    tags=["Risk"]
)


@router.get("/")
def list_risks(db: Session = Depends(get_db)):
    """
    List all calculated risks
    """
    return db.query(Risk).all()
