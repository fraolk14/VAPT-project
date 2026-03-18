from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.services.reporting import export_findings_csv, export_findings_json

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/findings.json", response_class=PlainTextResponse)
def export_json(db: Session = Depends(get_db)):
    return export_findings_json(db.query(Finding).all())


@router.get("/findings.csv", response_class=PlainTextResponse)
def export_csv(db: Session = Depends(get_db)):
    return export_findings_csv(db.query(Finding).all())
