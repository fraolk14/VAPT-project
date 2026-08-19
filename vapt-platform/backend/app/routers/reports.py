from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.security import decode_token, jwt, SECRET_KEY, ALGORITHM
from app.services.reporting import (
    REPORT_UPLOADS_DIR,
    build_report_preview,
    ensure_report_storage,
    export_findings_csv,
    export_findings_docx,
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
    format: str = "pdf"
    selected_targets: list[str] = Field(default_factory=list)
    report_title: str | None = None
    company_name: str | None = None
    author_name: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    include_cves: bool = True
    include_remediation: bool = True
    include_raw_scan: bool = True
    include_compliance_map: bool = True


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


@router.post("/findings.docx")
def export_docx_custom(payload: ReportRequest, db: Session = Depends(get_db)):
    normalized_mode = _normalize_mode(payload.mode)
    docx_payload = export_findings_docx(
        db.query(Finding).all(),
        mode=normalized_mode,
        selected_targets=payload.selected_targets,
        report_title=payload.report_title,
    )
    return Response(
        content=docx_payload,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename=findings-report-{normalized_mode}.docx"},
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


@router.get("/data/{scan_job_id}")
@router.get("/v1/data/{scan_job_id}")
def get_report_data(scan_job_id: str, db: Session = Depends(get_db)):
    from app.models.misconfiguration import MisconfigAsset, Misconfiguration, ScanJob

    job = None
    if scan_job_id not in {"latest", "null", "undefined"}:
        try:
            job_id_int = int(scan_job_id)
            job = db.get(ScanJob, job_id_int)
        except ValueError:
            pass

    if not job:
        job = db.query(ScanJob).order_by(ScanJob.id.desc()).first()

    if not job:
        return {
            "scan_job_id": None,
            "scope": None,
            "scope_type": None,
            "status": "COMPLETED",
            "summary": {
                "total_assets": 0,
                "total_findings": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "compliance_score": 100,
            },
            "assets": [],
            "misconfigurations": [],
            "compliance_map": []
        }

    assets = db.query(MisconfigAsset).filter(MisconfigAsset.scan_job_id == job.id).all()
    asset_ids = [a.id for a in assets]
    misconfigs = db.query(Misconfiguration).filter(Misconfiguration.asset_id.in_(asset_ids)).all() if asset_ids else []

    findings = db.query(Finding).all()

    crit_cnt = len([m for m in misconfigs if m.severity.upper() == "CRITICAL"]) + len([f for f in findings if (f.severity or "").lower() == "critical"])
    high_cnt = len([m for m in misconfigs if m.severity.upper() == "HIGH"]) + len([f for f in findings if (f.severity or "").lower() == "high"])
    med_cnt = len([m for m in misconfigs if m.severity.upper() == "MEDIUM"]) + len([f for f in findings if (f.severity or "").lower() == "medium"])
    low_cnt = len([m for m in misconfigs if m.severity.upper() == "LOW"]) + len([f for f in findings if (f.severity or "").lower() == "low"])

    total_assets_cnt = max(1, len(assets) or len(set(m.hostname for m in assets if m.hostname)))
    penalty = (crit_cnt * 25 + high_cnt * 12 + med_cnt * 5 + low_cnt * 1) / (total_assets_cnt * 2)
    comp_score = min(100, max(20, round(100 - penalty)))

    asset_list = [
        {
            "id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "asset_type": a.asset_type,
            "os_type": a.os_type,
            "discovered_at": a.discovered_at.isoformat() if a.discovered_at else None,
        }
        for a in assets
    ]

    misconfig_list = [
        {
            "id": f"m_{m.id}",
            "asset_id": m.asset_id,
            "ip": db.get(MisconfigAsset, m.asset_id).ip if db.get(MisconfigAsset, m.asset_id) else "127.0.0.1",
            "hostname": db.get(MisconfigAsset, m.asset_id).hostname if db.get(MisconfigAsset, m.asset_id) else job.scope,
            "asset_type": db.get(MisconfigAsset, m.asset_id).asset_type if db.get(MisconfigAsset, m.asset_id) else "OS",
            "port": 443 if "Web" in m.issue or "HTTP" in m.issue else 22,
            "issue": m.issue,
            "severity": m.severity.upper(),
            "cve": m.cve,
            "detected_by": m.detected_by,
            "remediation": m.remediation,
            "status": m.status,
            "discovered_at": m.discovered_at.isoformat() if m.discovered_at else None,
        }
        for m in misconfigs
    ]

    for f in findings:
        metadata = f.finding_metadata or {}
        misconfig_list.append({
            "id": f"f_{f.id}",
            "asset_id": 0,
            "ip": metadata.get("host") or metadata.get("ip_address") or "127.0.0.1",
            "hostname": metadata.get("url") or metadata.get("host") or f.source,
            "asset_type": "Website" if f.source == "zap" else "OS",
            "port": metadata.get("port", 443),
            "issue": f.title,
            "severity": (f.severity or "MEDIUM").upper(),
            "cve": f.cve_id,
            "detected_by": f.source,
            "remediation": f.remediation or "Apply security updates and review configuration.",
            "status": f.status or "OPEN",
            "discovered_at": f.detected_at.isoformat() if f.detected_at else datetime.now(timezone.utc).isoformat(),
        })

    compliance_map = [
        {
            "finding_id": item["id"],
            "issue": item["issue"],
            "severity": item["severity"],
            "cis": True if "SSH" in item["issue"] or "CIS" in item.get("detected_by", "") else False,
            "nist": True if item["severity"] in {"CRITICAL", "HIGH"} else False,
            "gdpr": True if "Exposed" in item["issue"] or "Password" in item["issue"] else False,
            "hipaa": True if item["severity"] == "CRITICAL" else False,
            "soc2": True if "CORS" in item["issue"] or "Credentials" in item["issue"] else False,
            "iso27001": True,
        }
        for item in misconfig_list
    ]

    return {
        "scan_job_id": job.id,
        "scope": job.scope,
        "scope_type": job.scope_type,
        "status": job.status,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "summary": {
            "total_assets": len(asset_list) or len(set(m["hostname"] for m in misconfig_list)),
            "total_findings": len(misconfig_list),
            "critical_count": crit_cnt,
            "high_count": high_cnt,
            "medium_count": med_cnt,
            "low_count": low_cnt,
            "compliance_score": comp_score,
        },
        "assets": asset_list,
        "misconfigurations": misconfig_list,
        "compliance_map": compliance_map,
    }


@router.post("/logo")
@router.post("/v1/logo")
async def upload_logo_v1(
    company_name: str | None = Form(default=None),
    file: UploadFile = File(...),
):
    ensure_report_storage()
    suffix = Path(file.filename or "logo").suffix.lower()
    if suffix not in {".png", ".jpg", ".jpeg", ".svg"}:
        return Response(content='{"detail":"Supported logo formats: PNG, JPG, JPEG, SVG."}', media_type="application/json", status_code=400)
    destination = REPORT_UPLOADS_DIR / f"report-logo{suffix}"
    content = await file.read()
    destination.write_bytes(content)
    branding = save_report_branding(company_name=company_name, logo_path=str(destination), logo_name=file.filename or destination.name)
    return {
        "company_name": branding["company_name"],
        "logo_name": branding.get("logo_name"),
        "logo_uploaded": True,
        "logo_url": f"/api/reports/uploads/{destination.name}",
        "updated_at": branding.get("updated_at"),
    }


@router.post("/download/{scan_job_id}")
@router.post("/v1/download/{scan_job_id}")
def download_report_file_post(
    scan_job_id: str,
    payload: ReportRequest,
    db: Session = Depends(get_db),
):
    normalized_mode = _normalize_mode(payload.mode)
    fmt = (payload.format or "pdf").strip().lower()
    findings = db.query(Finding).all()

    if fmt == "csv":
        csv_data = export_findings_csv(findings)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=VAPT_{(payload.company_name or 'Platform').replace(' ', '_')}_{normalized_mode}_Report.csv"},
        )
    if fmt == "json":
        data_json = export_findings_json(findings)
        return Response(
            content=data_json,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=VAPT_{(payload.company_name or 'Platform').replace(' ', '_')}_{normalized_mode}_Report.json"},
        )
    if fmt == "docx":
        docx_bytes = export_findings_docx(
            findings,
            mode=normalized_mode,
            report_title=payload.report_title,
            company_name=payload.company_name,
        )
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=VAPT_{(payload.company_name or 'Platform').replace(' ', '_')}_{normalized_mode}_Report.docx"},
        )

    # Default to PDF
    pdf_bytes = export_findings_pdf(
        findings,
        mode=normalized_mode,
        report_title=payload.report_title,
        company_name=payload.company_name,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=VAPT_{(payload.company_name or 'Platform').replace(' ', '_')}_{normalized_mode}_Report.pdf"},
    )


@router.get("/download/{scan_job_id}")
@router.get("/v1/download/{scan_job_id}")
def download_report_file_get(
    scan_job_id: str,
    type: str = Query(default="executive"),
    format: str = Query(default="pdf"),
    company_name: str | None = Query(default=None),
    report_title: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    import uuid
    normalized_mode = _normalize_mode(type)
    fmt = (format or "pdf").strip().lower()
    
    scan = None
    if scan_job_id and scan_job_id not in ["all", "latest", "default"]:
        try:
            valid_uuid = uuid.UUID(str(scan_job_id))
            scan = db.query(Scan).filter(Scan.id == valid_uuid).first()
        except (ValueError, TypeError):
            # If scan_job_id is integer string, try finding by target or recent scan
            scan = db.query(Scan).filter(Scan.target == scan_job_id).first()
            if not scan:
                scan = db.query(Scan).order_by(Scan.created_at.desc()).first()

    if scan:
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        if not findings and scan.target:
            findings = db.query(Finding).filter(Finding.target.like(f"%{scan.target}%")).all()
        if not report_title:
            report_title = f"{scan.scan_name} (Assessment: {scan.target})"
    else:
        findings = db.query(Finding).all()

    if fmt == "csv":
        csv_data = export_findings_csv(findings)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=VAPT_Scan_Report_{scan_job_id}_{normalized_mode}.csv"},
        )
    if fmt == "json":
        data_json = export_findings_json(findings)
        return Response(
            content=data_json,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=VAPT_Scan_Report_{scan_job_id}_{normalized_mode}.json"},
        )
    if fmt == "docx":
        docx_bytes = export_findings_docx(findings, mode=normalized_mode, report_title=report_title, company_name=company_name)
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=VAPT_Scan_Report_{scan_job_id}_{normalized_mode}.docx"},
        )

    # Default to PDF
    pdf_bytes = export_findings_pdf(findings, mode=normalized_mode, report_title=report_title, company_name=company_name)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=VAPT_Scan_Report_{scan_job_id}_{normalized_mode}.pdf"},
    )
