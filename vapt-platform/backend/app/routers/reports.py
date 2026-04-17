from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.services.reporting import export_findings_csv, export_findings_json, export_findings_pdf, summarize_findings

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/findings.json", response_class=PlainTextResponse)
def export_json(db: Session = Depends(get_db)):
    return export_findings_json(db.query(Finding).all())


@router.get("/findings.csv", response_class=PlainTextResponse)
def export_csv(db: Session = Depends(get_db)):
    return export_findings_csv(db.query(Finding).all())


@router.get("/summary")
def report_summary(db: Session = Depends(get_db)):
    return summarize_findings(db.query(Finding).all())


@router.get("/findings.pdf")
def export_pdf(db: Session = Depends(get_db)):
    payload = export_findings_pdf(db.query(Finding).all())
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=findings-report.pdf"},
    )
