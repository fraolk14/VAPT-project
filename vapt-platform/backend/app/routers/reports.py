from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.services.security import decode_token, jwt, SECRET_KEY, ALGORITHM
from app.services.reporting import (
    REPORT_UPLOADS_DIR,
    build_report_preview,
    ensure_report_storage,
    export_findings_csv,
    export_findings_json,
    export_findings_pdf,
    load_report_branding,
    report_targets,
    save_report_branding,
    summarize_findings,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


class ReportRequest(BaseModel):
    mode: str = "executive"
    selected_targets: list[str] = Field(default_factory=list)
    report_title: str | None = None


class ReportDownloadLinkResponse(BaseModel):
    download_url: str
    expires_in: int = 300


def _normalize_mode(mode: str | None) -> str:
    normalized_mode = (mode or "executive").strip().lower()
    if normalized_mode not in {"executive", "technical", "compliance"}:
        normalized_mode = "executive"
    return normalized_mode


def _issue_download_token(payload: ReportRequest) -> tuple[str, int]:
    expires_in = 300
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    token = jwt.encode(
        {
            "type": "report_download",
            "mode": _normalize_mode(payload.mode),
            "selected_targets": payload.selected_targets,
            "report_title": payload.report_title,
            "exp": expires_at,
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )
    return token, expires_in


@router.get("/findings.json", response_class=PlainTextResponse)
def export_json(db: Session = Depends(get_db)):
    return export_findings_json(db.query(Finding).all())


@router.get("/findings.csv", response_class=PlainTextResponse)
def export_csv(db: Session = Depends(get_db)):
    return export_findings_csv(db.query(Finding).all())


@router.get("/summary")
def report_summary(db: Session = Depends(get_db)):
    return summarize_findings(db.query(Finding).all())


@router.get("/targets")
def list_report_targets(db: Session = Depends(get_db)):
    return report_targets(db.query(Finding).all())


@router.get("/branding")
def get_branding():
    branding = load_report_branding()
    return {
        "company_name": branding["company_name"],
        "logo_name": branding.get("logo_name"),
        "logo_uploaded": bool(branding.get("logo_path") and Path(branding["logo_path"]).exists()),
        "updated_at": branding.get("updated_at"),
    }


@router.post("/branding/logo")
async def upload_brand_logo(
    company_name: str | None = Form(default=None),
    file: UploadFile = File(...),
):
    ensure_report_storage()
    suffix = Path(file.filename or "logo").suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg"}:
        return Response(content='{"detail":"Only PNG and JPG logos are supported."}', media_type="application/json", status_code=400)
    destination = REPORT_UPLOADS_DIR / f"report-logo{suffix}"
    content = await file.read()
    destination.write_bytes(content)
    branding = save_report_branding(company_name=company_name, logo_path=str(destination), logo_name=file.filename or destination.name)
    return {
        "company_name": branding["company_name"],
        "logo_name": branding.get("logo_name"),
        "logo_uploaded": True,
        "updated_at": branding.get("updated_at"),
    }


@router.post("/preview")
def preview_report(payload: ReportRequest, db: Session = Depends(get_db)):
    normalized_mode = _normalize_mode(payload.mode)
    return build_report_preview(
        db.query(Finding).all(),
        mode=normalized_mode,
        selected_targets=payload.selected_targets,
        report_title=payload.report_title,
    )


@router.post("/download-link", response_model=ReportDownloadLinkResponse)
def create_download_link(payload: ReportRequest):
    token, expires_in = _issue_download_token(payload)
    return ReportDownloadLinkResponse(download_url=f"/api/reports/findings.pdf/download?token={token}", expires_in=expires_in)


@router.post("/findings.pdf")
def export_pdf_custom(payload: ReportRequest, db: Session = Depends(get_db)):
    normalized_mode = _normalize_mode(payload.mode)
    pdf_payload = export_findings_pdf(
        db.query(Finding).all(),
        mode=normalized_mode,
        selected_targets=payload.selected_targets,
        report_title=payload.report_title,
    )
    return Response(
        content=pdf_payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=findings-report-{normalized_mode}.pdf"},
    )


@router.get("/findings.pdf/download")
def export_pdf_from_token(token: str = Query(...), db: Session = Depends(get_db)):
    try:
        payload = decode_token(token)
    except Exception as exc:
        return Response(content='{"detail":"Invalid or expired report download token."}', media_type="application/json", status_code=400)
    if payload.get("type") != "report_download":
        return Response(content='{"detail":"Invalid report download token."}', media_type="application/json", status_code=400)
    normalized_mode = _normalize_mode(payload.get("mode"))
    pdf_payload = export_findings_pdf(
        db.query(Finding).all(),
        mode=normalized_mode,
        selected_targets=payload.get("selected_targets") or [],
        report_title=payload.get("report_title"),
    )
    return Response(
        content=pdf_payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=findings-report-{normalized_mode}.pdf"},
    )


@router.get("/findings.pdf")
def export_pdf(mode: str = Query(default="executive"), db: Session = Depends(get_db)):
    normalized_mode = _normalize_mode(mode)
    payload = export_findings_pdf(db.query(Finding).all(), mode=normalized_mode)
    return Response(
        content=payload,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=findings-report-{normalized_mode}.pdf"},
    )
