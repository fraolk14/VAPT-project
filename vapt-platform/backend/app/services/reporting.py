import csv
import io
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.models.finding import Finding

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:  # pragma: no cover
    colors = None
    TA_LEFT = 0
    letter = None
    getSampleStyleSheet = None
    ParagraphStyle = None
    inch = 72
    Image = object
    PageBreak = object
    Paragraph = object
    SimpleDocTemplate = object
    Spacer = object
    Table = object
    TableStyle = object

try:
    from docx import Document
except Exception:  # pragma: no cover
    Document = None


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
REPORT_DATA_DIR = Path(__file__).resolve().parents[1] / "data"
REPORT_BRANDING_PATH = REPORT_DATA_DIR / "report_branding.json"
REPORT_UPLOADS_DIR = REPORT_DATA_DIR / "uploads"


def ensure_report_storage() -> None:
    REPORT_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    if not REPORT_BRANDING_PATH.exists():
        REPORT_BRANDING_PATH.write_text(
            json.dumps(
                {
                    "company_name": "VAPTICOM",
                    "logo_path": None,
                    "logo_name": None,
                    "updated_at": None,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def load_report_branding() -> dict:
    ensure_report_storage()
    try:
        payload = json.loads(REPORT_BRANDING_PATH.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    return {
        "company_name": payload.get("company_name") or "VAPTICOM",
        "logo_path": payload.get("logo_path"),
        "logo_name": payload.get("logo_name"),
        "updated_at": payload.get("updated_at"),
    }


def save_report_branding(*, company_name: str | None = None, logo_path: str | None = None, logo_name: str | None = None) -> dict:
    current = load_report_branding()
    if company_name:
        current["company_name"] = company_name
    if logo_path is not None:
        current["logo_path"] = logo_path
    if logo_name is not None:
        current["logo_name"] = logo_name
    current["updated_at"] = datetime.now(timezone.utc).isoformat()
    REPORT_BRANDING_PATH.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def _finding_target(finding: Finding) -> str:
    metadata = finding.finding_metadata or {}
    for key in ("target", "affected_url", "host", "hostname", "ip_address", "url"):
        value = metadata.get(key)
        if value:
            return str(value)
    if finding.service:
        return f"{finding.service}:{finding.port}"
    return f"port {finding.port}"


def _serialize_finding(finding: Finding) -> dict:
    metadata = finding.finding_metadata or {}
    target = _finding_target(finding)
    return {
        "id": str(finding.id),
        "title": finding.title,
        "source": finding.source,
        "severity": finding.severity,
        "status": finding.status,
        "cvss_score": finding.cvss_score,
        "cve_id": finding.cve_id,
        "compliance_map": finding.compliance_map or [],
        "remediation": finding.remediation,
        "target": target,
        "asset_name": metadata.get("asset_name") or metadata.get("hostname") or target,
        "hostname": metadata.get("hostname") or metadata.get("host"),
        "ip_address": metadata.get("ip_address") or metadata.get("host"),
        "url": metadata.get("url") or metadata.get("affected_url"),
        "evidence": finding.evidence,
        "references": metadata.get("references", []),
        "os_family": metadata.get("os_family"),
        "cis_benchmark": metadata.get("cis_benchmark"),
        "hardening_recommendation": metadata.get("hardening_recommendation"),
        "assigned_to": finding.assigned_to,
        "team_name": finding.team_name,
        "verification_state": finding.verification_state,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
    }


def _format_dt(value: str | None) -> str:
    if not value:
        return "n/a"
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%d-%m-%Y %H:%M UTC")
    except Exception:
        return value


def export_findings_json(findings: Iterable[Finding]) -> str:
    return json.dumps([_serialize_finding(finding) for finding in findings], indent=2)


def export_findings_csv(findings: Iterable[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "id",
            "title",
            "target",
            "asset_name",
            "hostname",
            "ip_address",
            "url",
            "source",
            "severity",
            "status",
            "verification_state",
            "cvss_score",
            "cve_id",
            "os_family",
            "cis_benchmark",
            "assigned_to",
            "team_name",
            "detected_at",
            "remediation",
            "evidence",
        ]
    )
    for finding in findings:
        row = _serialize_finding(finding)
        writer.writerow(
            [
                row["id"],
                row["title"],
                row["target"],
                row["asset_name"],
                row["hostname"],
                row["ip_address"],
                row["url"],
                row["source"],
                row["severity"],
                row["status"],
                row["verification_state"],
                row["cvss_score"],
                row["cve_id"],
                row["os_family"],
                row["cis_benchmark"],
                row["assigned_to"],
                row["team_name"],
                row["detected_at"],
                row["remediation"],
                row["evidence"],
            ]
        )
    return buffer.getvalue()


def summarize_findings(findings: Iterable[Finding]) -> dict:
    finding_list = list(findings)
    severity_counts = Counter((finding.severity or "info").lower() for finding in finding_list)
    source_counts = Counter(finding.source for finding in finding_list)
    compliance_counts = Counter(item for finding in finding_list for item in (finding.compliance_map or []))
    top_items = sorted(
        finding_list,
        key=lambda finding: ((finding.cvss_score or 0), SEVERITY_ORDER.get((finding.severity or "info").lower(), 0)),
        reverse=True,
    )[:10]
    return {
        "total_findings": len(finding_list),
        "open_findings": sum(1 for finding in finding_list if finding.status == "open"),
        "severity_counts": dict(severity_counts),
        "source_counts": dict(source_counts),
        "compliance_counts": dict(compliance_counts),
        "top_findings": [_serialize_finding(finding) for finding in top_items],
    }


def _severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get((severity or "info").lower(), 0)


def _scope_targets(items: list[dict]) -> list[str]:
    ordered = []
    seen = set()
    for item in items:
        target = item.get("target")
        if target and target not in seen:
            ordered.append(target)
            seen.add(target)
    return ordered


def _styles():
    styles = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            textColor=colors.HexColor("#10283f"),
            alignment=TA_LEFT,
            spaceAfter=18,
        ),
        "title": ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0d2338"),
            spaceAfter=12,
        ),
        "section": ParagraphStyle(
            "Section",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#10283f"),
            spaceBefore=10,
            spaceAfter=8,
        ),
        "subsection": ParagraphStyle(
            "SubSection",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#15324d"),
            spaceBefore=6,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.4,
            leading=13,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#1b2f44"),
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.2,
            leading=11,
            textColor=colors.HexColor("#44576a"),
            spaceAfter=3,
        ),
        "table": ParagraphStyle(
            "TableCell",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1b2f44"),
        ),
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=TA_LEFT,
        ),
    }


def _header_drawer(company_name: str, logo_path: str | None):
    def _draw(canvas, doc):
        canvas.saveState()
        if logo_path and Path(logo_path).exists():
            try:
                canvas.drawImage(logo_path, 38, 736, width=120, height=36, preserveAspectRatio=True, mask="auto")
            except Exception:
                canvas.setFillColor(colors.HexColor("#18b4b0"))
                canvas.roundRect(38, 738, 34, 34, 8, stroke=0, fill=1)
                canvas.setFillColor(colors.white)
                canvas.setFont("Helvetica-Bold", 18)
                canvas.drawCentredString(55, 748, "V")
        else:
            canvas.setFillColor(colors.HexColor("#18b4b0"))
            canvas.roundRect(38, 738, 34, 34, 8, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 18)
            canvas.drawCentredString(55, 748, "V")
        canvas.setFillColor(colors.HexColor("#10283f"))
        canvas.setFont("Helvetica-Bold", 16)
        canvas.drawString(168 if logo_path and Path(logo_path).exists() else 82, 754, company_name)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#57697d"))
        canvas.drawString(168 if logo_path and Path(logo_path).exists() else 82, 742, "Vulnerability Assessment and Penetration Testing")
        canvas.setStrokeColor(colors.HexColor("#d7e3ec"))
        canvas.line(38, 734, 574, 734)
        canvas.setFillColor(colors.HexColor("#6c7f93"))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(572, 24, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    return _draw


def _table_cell(value, style):
    if isinstance(value, Paragraph):
        return value
    if value is None:
        value = ""
    paragraph = Paragraph(str(value), style)
    return paragraph


def _table(rows, col_widths):
    styles = _styles()
    normalized_rows = []
    for row_index, row in enumerate(rows):
        style = styles["table_header"] if row_index == 0 else styles["table"]
        normalized_rows.append([_table_cell(cell, style) for cell in row])
    table = Table(normalized_rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#10283f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d4dde5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f9fc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]
        )
    )
    return table


def _severity_table(serialized_findings: list[dict]):
    counts = Counter((item.get("severity") or "info").lower() for item in serialized_findings)
    rows = [["Severity", "Count"]]
    for severity in ("critical", "high", "medium", "low", "info"):
        rows.append([severity.title(), str(counts.get(severity, 0))])
    styles = _styles()
    normalized_rows = [[_table_cell(cell, styles["table"]) for cell in row] for row in rows]
    table = Table(normalized_rows, colWidths=[2.0 * inch, 1.2 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#10283f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d4dde5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f8fb")]),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEADING", (0, 0), (-1, -1), 11),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]
        )
    )
    return table


def _group_by_target(serialized_findings: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in serialized_findings:
        grouped[item.get("target") or "Unknown target"].append(item)
    return grouped


def _document_control_table(company_name: str, report_title: str, serialized_findings: list[dict], normalized_mode: str):
    targets = _scope_targets(serialized_findings)
    dates = [item.get("detected_at") for item in serialized_findings if item.get("detected_at")]
    start_date = _format_dt(min(dates)) if dates else "n/a"
    end_date = _format_dt(max(dates)) if dates else "n/a"
    rows = [
        ["Document type", report_title],
        ["Document owner", company_name],
        ["Assessment type", f"{normalized_mode.title()} security assessment"],
        ["Report date", datetime.now(timezone.utc).strftime("%d-%m-%Y")],
        ["Assessment period", f"{start_date} to {end_date}"],
        ["Targets in scope", str(len(targets))],
        ["Findings in scope", str(len(serialized_findings))],
    ]
    return _table([["Field", "Value"], *rows], [1.8 * inch, 4.6 * inch])


def _toc_table():
    rows = [
        ["1", "Introduction and assessment overview"],
        ["2", "Methodology and approach"],
        ["3", "Assessment scope"],
        ["4", "Risk level and description"],
        ["5", "Tools used during assessment"],
        ["6", "Disclaimer and assumptions"],
        ["7", "Executive summary report"],
        ["8", "Detailed report by target and finding"],
        ["9", "Compliance impact and re-test guidance"],
    ]
    return _table([["Section", "Description"], *rows], [1.0 * inch, 5.4 * inch])


def _risk_level_table():
    rows = [
        ["Critical", "CVSS 9.0-10.0", "Complete compromise or major business impact."],
        ["High", "CVSS 7.0-8.9", "Sensitive exposure or straightforward exploitation."],
        ["Medium", "CVSS 4.0-6.9", "Partial control or moderate security weakness."],
        ["Low", "CVSS 0.1-3.9", "Limited impact or hard-to-exploit weakness."],
        ["Informational", "Best practice", "Improvement item that can become security debt later."],
    ]
    return _table([["Risk", "Range", "Description"], *rows], [1.1 * inch, 1.2 * inch, 4.1 * inch])


def _tools_table(serialized_findings: list[dict]):
    source_map = {
        "openvas": "Network vulnerability scanning and service enumeration",
        "zap": "Web application crawling and vulnerability testing",
        "mobsf": "Mobile application static and metadata review",
        "network-db": "Database-backed network correlation and vulnerability enrichment",
        "platform": "Platform-side posture and workflow validation",
        "github-actions": "CI/CD or workflow security telemetry",
    }
    counts = Counter(item.get("source") or "unknown" for item in serialized_findings)
    rows = [["Tool / Engine", "Usage", "Findings"]]
    for source, count in counts.items():
        rows.append([source, source_map.get(source, "Security telemetry or enrichment source"), str(count)])
    return _table(rows, [1.5 * inch, 3.7 * inch, 1.1 * inch])


def _target_summary_table(grouped_by_asset: dict[str, list[dict]]):
    rows = [["Sl. No.", "Target", "Critical", "High", "Medium", "Low", "Info", "Total"]]
    for index, (target, entries) in enumerate(grouped_by_asset.items(), start=1):
        counts = Counter((entry.get("severity") or "info").lower() for entry in entries)
        rows.append(
            [
                str(index),
                target,
                str(counts.get("critical", 0)),
                str(counts.get("high", 0)),
                str(counts.get("medium", 0)),
                str(counts.get("low", 0)),
                str(counts.get("info", 0)),
                str(len(entries)),
            ]
        )
    return _table(rows, [0.55 * inch, 2.2 * inch, 0.65 * inch, 0.6 * inch, 0.75 * inch, 0.55 * inch, 0.55 * inch, 0.65 * inch])


def _open_port_rows(entries: list[dict]):
    seen = set()
    rows = [["Port", "Protocol", "Service", "Source"]]
    for item in entries:
        key = (item.get("port"), item.get("protocol"), item.get("service"))
        if key in seen or not item.get("port"):
            continue
        seen.add(key)
        rows.append([
            str(item.get("port") or "n/a"),
            item.get("protocol") or "tcp",
            item.get("service") or "unknown",
            item.get("source") or "scanner",
        ])
    return rows


def _finding_summary_rows(entries: list[dict]):
    rows = [["Sl. No.", "Vulnerability name", "Risk", "CVSS", "Status"]]
    for index, item in enumerate(entries, start=1):
        rows.append([
            str(index),
            item.get("title") or "Finding",
            (item.get("severity") or "info").title(),
            str(item.get("cvss_score") or "n/a"),
            item.get("status") or "open",
        ])
    return rows


def _detail_table(item: dict):
    rows = [
        ["Target", item.get("target") or "n/a"],
        ["Asset", item.get("asset_name") or "n/a"],
        ["Source", item.get("source") or "n/a"],
        ["Severity", (item.get("severity") or "info").title()],
        ["Status", item.get("status") or "open"],
        ["Verification", item.get("verification_state") or "pending"],
        ["CVE / CVSS", f"{item.get('cve_id') or 'n/a'} / {item.get('cvss_score') or 'n/a'}"],
        ["Platform", item.get("os_family") or "n/a"],
        ["CIS Benchmark", item.get("cis_benchmark") or "n/a"],
        ["Detected", item.get("detected_at") or "n/a"],
    ]
    styles = _styles()
    normalized_rows = [[_table_cell(cell, styles["table"]) for cell in row] for row in rows]
    table = Table(normalized_rows, colWidths=[1.4 * inch, 4.8 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eff5fa")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#10283f")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d4dde5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("LEADING", (0, 0), (-1, -1), 10.5),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]
        )
    )
    return table


def _reference_lines(item: dict) -> list[str]:
    refs = list(dict.fromkeys(item.get("references") or []))
    if item.get("cve_id"):
        refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{item['cve_id']}")
        refs.insert(1, f"https://www.cve.org/CVERecord?id={item['cve_id']}")
    return [ref for ref in refs if ref][:6]


def report_targets(findings: Iterable[Finding]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for finding in findings:
        item = _serialize_finding(finding)
        key = item.get("target") or item.get("asset_name") or str(item["id"])
        bucket = grouped.setdefault(
            key,
            {
                "target": key,
                "asset_name": item.get("asset_name") or key,
                "hostname": item.get("hostname"),
                "ip_address": item.get("ip_address"),
                "url": item.get("url"),
                "os_family": item.get("os_family"),
                "finding_count": 0,
                "highest_severity": "info",
            },
        )
        bucket["finding_count"] += 1
        if _severity_rank(item.get("severity")) > _severity_rank(bucket.get("highest_severity")):
            bucket["highest_severity"] = item.get("severity") or "info"
        for field in ("hostname", "ip_address", "url", "os_family"):
            if not bucket.get(field) and item.get(field):
                bucket[field] = item.get(field)
    return sorted(grouped.values(), key=lambda entry: (_severity_rank(entry.get("highest_severity")), entry.get("finding_count", 0), entry.get("target") or ""), reverse=True)


def filter_findings(findings: Iterable[Finding], selected_targets: list[str] | None = None) -> list[Finding]:
    selected = {value.strip().lower() for value in (selected_targets or []) if value and value.strip()}
    if not selected:
        return list(findings)
    filtered = []
    for finding in findings:
        item = _serialize_finding(finding)
        candidates = {
            (item.get("target") or "").lower(),
            (item.get("asset_name") or "").lower(),
            (item.get("hostname") or "").lower(),
            (item.get("ip_address") or "").lower(),
            (item.get("url") or "").lower(),
        }
        if candidates & selected:
            filtered.append(finding)
    return filtered


def _build_executive_summary(serialized_findings: list[dict], summary: dict) -> dict:
    severity_counts = summary.get("severity_counts", {})
    priority_entries = [item for item in serialized_findings if _severity_rank(item.get("severity")) >= 3][:5]
    top_priority_findings = [
        {
            "title": item.get("title") or "Untitled finding",
            "severity": (item.get("severity") or "info").title(),
            "target": item.get("target") or "Unspecified target",
            "cvss_score": item.get("cvss_score") or "n/a",
            "remediation": item.get("remediation") or item.get("hardening_recommendation") or "Apply the remediation guidance recorded with the finding.",
        }
        for item in priority_entries
    ]

    grouped_targets: dict[str, list[dict]] = defaultdict(list)
    for item in serialized_findings:
        grouped_targets[item.get("target") or "Unknown target"].append(item)
    highest_risk_targets = []
    for target, entries in sorted(
        grouped_targets.items(),
        key=lambda entry: (_severity_rank(max((item.get("severity") for item in entry[1]), key=_severity_rank, default="info")), len(entry[1])),
        reverse=True,
    )[:5]:
        highest_risk_targets.append(
            {
                "target": target,
                "finding_count": len(entries),
                "highest_severity": max((item.get("severity") or "info" for item in entries), key=_severity_rank, default="info"),
            }
        )

    summary_text = (
        f"The assessment identified {summary.get('total_findings', 0)} findings across the selected scope. "
        f"{summary.get('open_findings', 0)} remain open and should be tracked through a remediation plan with clear ownership."
    )
    recommendations = []
    if severity_counts.get("critical", 0):
        recommendations.append("Contain and validate all critical-risk issues immediately, especially on internet-facing or business-critical targets.")
    if severity_counts.get("high", 0):
        recommendations.append("Prioritize high-severity remediation work and confirm the fixes with re-testing before closing the items.")
    if summary.get("compliance_counts"):
        recommendations.append("Map the most significant findings to their compliance obligations and maintain evidence for audit or re-test review.")
    if not recommendations:
        recommendations.append("Review the current backlog and confirm that remediation owners and timelines have been assigned.")

    return {
        "summary_text": summary_text,
        "top_priority_findings": top_priority_findings,
        "highest_risk_targets": highest_risk_targets,
        "recommendations": recommendations,
    }


def build_report_preview(findings: Iterable[Finding], *, mode: str = "executive", selected_targets: list[str] | None = None, report_title: str | None = None) -> dict:
    filtered = filter_findings(findings, selected_targets)
    serialized = [_serialize_finding(item) for item in filtered]
    serialized.sort(
        key=lambda item: (_severity_rank(item.get("severity")), item.get("cvss_score") or 0, item.get("detected_at") or ""),
        reverse=True,
    )
    summary = summarize_findings(filtered)
    grouped_by_asset: dict[str, list[dict]] = defaultdict(list)
    for item in serialized:
        grouped_by_asset[item.get("target") or "Unknown target"].append(item)
    branding = load_report_branding()
    executive_summary = _build_executive_summary(serialized, summary)
    return {
        "mode": (mode or "executive").lower(),
        "report_title": report_title or f"{branding['company_name']} Security Assessment Report",
        "company_name": branding["company_name"],
        "logo_name": branding.get("logo_name"),
        "selected_targets": selected_targets or [],
        "summary": summary,
        "targets": _scope_targets(serialized),
        "findings_by_asset": [
            {
                "target": target,
                "finding_count": len(entries),
                "highest_severity": max((entry.get("severity") for entry in entries), key=_severity_rank, default="info"),
                "findings": entries[:5],
            }
            for target, entries in list(grouped_by_asset.items())[:20]
        ],
        "top_findings": serialized[:10],
        "executive_summary": executive_summary,
        "recommendations": executive_summary["recommendations"],
    }


def _add_docx_table(document, rows: list[list[str]]):
    if not rows:
        return
    table = document.add_table(rows=0, cols=len(rows[0]))
    table.style = "Table Grid"
    for row in rows:
        cells = table.add_row().cells
        for col_index, value in enumerate(row):
            paragraph = cells[col_index].paragraphs[0]
            paragraph.clear()
            paragraph.add_run().text = str(value)


def export_findings_docx(
    findings: Iterable[Finding],
    mode: str = "executive",
    *,
    selected_targets: list[str] | None = None,
    report_title: str | None = None,
    company_name: str | None = None,
) -> bytes:
    if Document is None:
        return b""

    filtered_findings = filter_findings(findings, selected_targets)
    serialized_findings = [_serialize_finding(item) for item in filtered_findings]
    serialized_findings.sort(
        key=lambda item: (_severity_rank(item.get("severity")), item.get("cvss_score") or 0, item.get("detected_at") or ""),
        reverse=True,
    )
    summary = summarize_findings(filtered_findings)
    executive_summary = _build_executive_summary(serialized_findings, summary)
    branding = load_report_branding()
    header_name = company_name or branding["company_name"]
    title = report_title or f"{header_name} Security Assessment Report"
    normalized_mode = (mode or "executive").lower()
    mode_title = {
        "executive": "Executive Report",
        "technical": "Technical Report",
        "compliance": "Compliance Report",
    }.get(normalized_mode, "Security Report")
    mode_intro = {
        "executive": "This report provides a management-ready view of the most important risks, the affected targets, and the remediation priorities that require near-term action.",
        "technical": "This report provides detailed technical findings, validation evidence, and remediation guidance for engineering and security operations teams.",
        "compliance": "This report explains the control impact of the identified findings, the relevant benchmark references, and the evidence needed for remediation and re-test closure.",
    }.get(normalized_mode, "This report summarizes the assessed findings and recommended next steps.")

    document = Document()
    document.add_heading(title, level=1)
    document.add_paragraph("Vulnerability Assessment and Penetration Testing Report")
    document.add_paragraph(f"Report mode: {mode_title}")
    document.add_paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}")
    document.add_paragraph(f"Company: {header_name}")
    document.add_paragraph(f"Targets in scope: {len(_scope_targets(serialized_findings))}")
    document.add_paragraph(f"Findings in scope: {summary['total_findings']}")
    document.add_paragraph(mode_intro)

    document.add_heading("Document control", level=2)
    _add_docx_table(
        document,
        [
            ["Field", "Value"],
            ["Document type", title],
            ["Document owner", header_name],
            ["Assessment type", f"{normalized_mode.title()} security assessment"],
            ["Report date", datetime.now(timezone.utc).strftime("%d-%m-%Y")],
            ["Targets in scope", str(len(_scope_targets(serialized_findings)))],
            ["Findings in scope", str(summary["total_findings"])],
        ],
    )

    document.add_heading("Notice of confidentiality", level=2)
    document.add_paragraph(
        "This document contains sensitive security assessment information and should be shared only with stakeholders responsible for risk acceptance, remediation, validation, or governance oversight."
    )

    document.add_heading("Table of contents", level=2)
    for section in [
        "1. Introduction",
        "2. Methodology and approach",
        "3. Assessment scope",
        "4. Risk level and description",
        "5. Tools used during assessment",
        "6. Disclaimer and assumptions",
        "7. Executive summary report",
        "8. Detailed report",
        "9. Compliance impact and re-test guidance",
    ]:
        document.add_paragraph(section, style="List Bullet")

    document.add_heading("1. Introduction", level=2)
    document.add_paragraph(
        "This report summarizes the vulnerability assessment and penetration testing results for the selected in-scope assets."
    )
    document.add_paragraph(
        "The objective of the assessment is to identify exploitable weaknesses, explain their business and technical impact, and provide clear remediation guidance that can be validated during re-test."
    )

    document.add_heading("2. Methodology and approach", level=2)
    document.add_paragraph(
        "The assessment combines network, web, mobile, and platform-originated telemetry where available. Findings are normalized, correlated, and severity-ranked using source evidence, CVSS context, and platform enrichment."
    )
    document.add_paragraph(
        "The workflow includes discovery, fingerprinting, vulnerability validation, evidence capture, enrichment, reporting, and re-test preparation."
    )

    document.add_heading("3. Assessment scope", level=2)
    targets = _scope_targets(serialized_findings)
    if not targets:
        document.add_paragraph("No targets were selected for this report scope.")
    else:
        _add_docx_table(document, [["Sl. No.", "Target", "OS / Platform"]] + [[str(index), target, (next((item.get("os_family") or "n/a" for item in serialized_findings if item.get("target") == target), "n/a"))] for index, target in enumerate(targets, start=1)])

    document.add_heading("4. Risk level and description", level=2)
    _add_docx_table(
        document,
        [
            ["Risk", "Range", "Description"],
            ["Critical", "CVSS 9.0-10.0", "Complete compromise or major business impact."],
            ["High", "CVSS 7.0-8.9", "Sensitive exposure or straightforward exploitation."],
            ["Medium", "CVSS 4.0-6.9", "Partial control or moderate security weakness."],
            ["Low", "CVSS 0.1-3.9", "Limited impact or hard-to-exploit weakness."],
            ["Informational", "Best practice", "Improvement item that can become security debt later."],
        ],
    )

    document.add_heading("5. Tools used during assessment", level=2)
    source_map = {
        "openvas": "Network vulnerability scanning and service enumeration",
        "zap": "Web application crawling and vulnerability testing",
        "mobsf": "Mobile application static and metadata review",
        "network-db": "Database-backed network correlation and vulnerability enrichment",
        "platform": "Platform-side posture and workflow validation",
        "github-actions": "CI/CD or workflow security telemetry",
    }
    counts = Counter(item.get("source") or "unknown" for item in serialized_findings)
    rows = [["Tool / Engine", "Usage", "Findings"]]
    for source, count in counts.items():
        rows.append([source, source_map.get(source, "Security telemetry or enrichment source"), str(count)])
    _add_docx_table(document, rows)

    document.add_heading("6. Disclaimer and assumptions", level=2)
    document.add_paragraph(
        "This report reflects the state of the assessed assets at the time of testing and within the limits of the configured scan depth, selected validation routines, available credentials, and reachable services."
    )
    document.add_paragraph(
        "Before implementing remediation, confirm that the affected service is required for business use, prepare backup and rollback plans, and schedule any disruptive changes through the appropriate operational process."
    )

    document.add_heading("7. Executive summary report", level=2)
    document.add_paragraph(executive_summary["summary_text"])
    document.add_paragraph(
        f"A total of {summary['total_findings']} findings are in scope. {summary['open_findings']} remain open."
    )
    document.add_paragraph("Priority findings", style="Intense Quote")
    for item in executive_summary["top_priority_findings"]:
        document.add_paragraph(
            f"• {item['title']} ({item['severity']}, CVSS {item['cvss_score']}) on {item['target']} — {item['remediation']}"
        )
    document.add_paragraph("Management actions", style="Intense Quote")
    for recommendation in executive_summary["recommendations"]:
        document.add_paragraph(f"• {recommendation}")
    _add_docx_table(document, [["Severity", "Count"], ["Critical", str(summary["severity_counts"].get("critical", 0))], ["High", str(summary["severity_counts"].get("high", 0))], ["Medium", str(summary["severity_counts"].get("medium", 0))], ["Low", str(summary["severity_counts"].get("low", 0))], ["Info", str(summary["severity_counts"].get("info", 0))]])

    document.add_heading("8. Detailed report", level=2)
    grouped_by_target = defaultdict(list)
    for item in serialized_findings:
        grouped_by_target[item.get("target") or "Unknown target"].append(item)
    for target, entries in grouped_by_target.items():
        document.add_heading(f"Target: {target}", level=3)
        document.add_paragraph("Summary of findings")
        _add_docx_table(document, [["Sl. No.", "Vulnerability name", "Risk", "CVSS", "Status"]] + [[str(index), entry.get("title") or "Finding", (entry.get("severity") or "info").title(), str(entry.get("cvss_score") or "n/a"), entry.get("status") or "open"] for index, entry in enumerate(entries, start=1)])
        for item in entries[:3]:
            document.add_paragraph(f"• {item.get('title')} — {item.get('severity') or 'info'}")

    document.add_heading("9. Compliance impact and re-test guidance", level=2)
    compliance_counts = Counter(tag for item in serialized_findings for tag in (item.get("compliance_map") or []))
    if compliance_counts:
        for tag, count in compliance_counts.most_common(10):
            document.add_paragraph(f"• {tag}: {count} related finding(s)")
    else:
        document.add_paragraph("No compliance mappings were available for the current report scope.")
    document.add_paragraph("Re-test guidance")
    for line in [
        "Re-test each affected target after remediation is completed.",
        "Validate that the vulnerability is no longer reproducible and that the service matches the intended secure state.",
        "Capture screenshots, configuration outputs, patch evidence, or scanner proof for closure.",
        "Where a fix cannot be implemented immediately, document the compensating control, risk owner, and next review date.",
    ]:
        document.add_paragraph(f"• {line}")

    output = io.BytesIO()
    document.save(output)
    return output.getvalue()


def export_findings_pdf(
    findings: Iterable[Finding],
    mode: str = "executive",
    *,
    selected_targets: list[str] | None = None,
    report_title: str | None = None,
    company_name: str | None = None,
    logo_path: str | None = None,
) -> bytes:
    if colors is None:
        return b"%PDF-1.4\n% Report engine unavailable\n"

    filtered_findings = filter_findings(findings, selected_targets)
    serialized_findings = [_serialize_finding(item) for item in filtered_findings]
    serialized_findings.sort(
        key=lambda item: (_severity_rank(item.get("severity")), item.get("cvss_score") or 0, item.get("detected_at") or ""),
        reverse=True,
    )
    summary = summarize_findings(filtered_findings)
    executive_summary = _build_executive_summary(serialized_findings, summary)
    styles = _styles()
    buffer = io.BytesIO()
    branding = load_report_branding()
    header_name = company_name or branding["company_name"]
    header_logo_path = logo_path or branding.get("logo_path")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=86,
        bottomMargin=38,
        title=report_title or f"{header_name} Security Report",
        author=header_name,
    )

    normalized_mode = (mode or "executive").lower()
    mode_title = {
        "executive": "Executive Report",
        "technical": "Technical Report",
        "compliance": "Compliance Report",
    }.get(normalized_mode, "Security Report")
    mode_intro = {
        "executive": "This report provides a management-ready view of the most important risks, the affected targets, and the remediation priorities that require near-term action.",
        "technical": "This report provides detailed technical findings, validation evidence, and remediation guidance for engineering and security operations teams.",
        "compliance": "This report explains the control impact of the identified findings, the relevant benchmark references, and the evidence needed for remediation and re-test closure.",
    }.get(normalized_mode, "This report summarizes the assessed findings and recommended next steps.")
    grouped_by_severity: dict[str, list[dict]] = defaultdict(list)
    grouped_by_asset = _group_by_target(serialized_findings)
    for item in serialized_findings:
        grouped_by_severity[(item.get("severity") or "info").lower()].append(item)

    targets = _scope_targets(serialized_findings)
    story = []

    story.extend(
        [
            Spacer(1, 60),
            Paragraph(header_name, styles["section"]),
            Paragraph(report_title or f"{header_name} Security Assessment Report", styles["cover_title"]),
            Paragraph("Vulnerability Assessment and Penetration Testing Report", styles["section"]),
            Spacer(1, 20),
            Paragraph(f"Report mode: {mode_title}", styles["body"]),
            Paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}", styles["body"]),
            Paragraph(f"Targets in scope: {len(targets)}", styles["body"]),
            Paragraph(f"Findings in scope: {summary['total_findings']}", styles["body"]),
            Spacer(1, 24),
            Paragraph(mode_intro, styles["body"]),
            PageBreak(),
            Paragraph("Document control", styles["title"]),
            _document_control_table(header_name, report_title or f"{header_name} Security Assessment Report", serialized_findings, normalized_mode),
            Spacer(1, 14),
            Paragraph("Notice of confidentiality", styles["section"]),
            Paragraph(
                "This document contains sensitive security assessment information. It should be shared only with stakeholders who are directly responsible for risk acceptance, remediation, validation, or governance oversight.",
                styles["body"],
            ),
            Spacer(1, 10),
            Paragraph("Table of contents", styles["section"]),
            _toc_table(),
            PageBreak(),
            Paragraph("1. Introduction", styles["title"]),
            Paragraph(
                "This report summarizes the vulnerability assessment and penetration testing results for the selected in-scope assets. It presents the assessment outcome in a communication format suitable for technical stakeholders, operational owners, and management review.",
                styles["body"],
            ),
            Paragraph(
                "The objective of the assessment is to identify exploitable weaknesses, explain their business and technical impact, and provide clear remediation guidance that can be validated during re-test.",
                styles["body"],
            ),
            Spacer(1, 8),
            Paragraph("2. Methodology and approach", styles["title"]),
            Paragraph(
                "The assessment combines network, web, mobile, and platform-originated telemetry where available. Findings are normalized, correlated, and severity-ranked using source evidence, CVSS context, and platform enrichment.",
                styles["body"],
            ),
            Paragraph(
                "The workflow typically includes discovery, fingerprinting, vulnerability validation, evidence capture, enrichment, reporting, and re-test preparation.",
                styles["body"],
            ),
            Spacer(1, 8),
            Paragraph("3. Assessment scope", styles["title"]),
        ]
    )

    if not targets:
        story.append(Paragraph("No targets were selected for this report scope.", styles["body"]))
    else:
        scope_rows = [["Sl. No.", "Target", "OS / Platform"]]
        for index, target in enumerate(targets, start=1):
            entries = grouped_by_asset.get(target, [])
            sample = entries[0] if entries else {}
            scope_rows.append([
                str(index),
                target,
                sample.get("os_family") or "n/a",
            ])
        story.append(_table(scope_rows, [0.55 * inch, 3.3 * inch, 2.2 * inch]))

    story.extend(
        [
            Spacer(1, 8),
            Paragraph("4. Risk level and description", styles["title"]),
            _risk_level_table(),
            Spacer(1, 8),
            Paragraph("5. Tools used during assessment", styles["title"]),
            _tools_table(serialized_findings),
            Spacer(1, 8),
            Paragraph("6. Disclaimer and assumptions", styles["title"]),
            Paragraph(
                "This report reflects the state of the assessed assets at the time of testing and within the limits of the configured scan depth, selected validation routines, available credentials, and reachable services.",
                styles["body"],
            ),
            Paragraph(
                "Before implementing remediation, confirm that the affected service is required for business use, prepare backup and rollback plans, and schedule any disruptive changes through the appropriate operational process.",
                styles["body"],
            ),
            Paragraph(
                "Some vulnerabilities may remain undetected if they require authenticated testing, deeper application context, environmental preconditions, or exploit paths intentionally excluded to avoid service disruption.",
                styles["body"],
            ),
            PageBreak(),
            Paragraph("7. Executive summary report", styles["title"]),
            Paragraph(executive_summary["summary_text"], styles["body"]),
            Paragraph(
                f"A total of <b>{summary['total_findings']}</b> findings are in scope. "
                f"<b>{summary['open_findings']}</b> findings remain open. "
                "Priority should be given to critical and high-severity weaknesses affecting exposed or business-critical targets.",
                styles["body"],
            ),
            Spacer(1, 8),
            Paragraph("Priority findings", styles["section"]),
            Paragraph(
                "The report highlights the most urgent issues that should be addressed first by the responsible stakeholders.",
                styles["body"],
            ),
        ]
    )
    for item in executive_summary["top_priority_findings"]:
        story.append(
            Paragraph(
                f"• {item['title']} ({item['severity']}, CVSS {item['cvss_score']}) on {item['target']} — {item['remediation']}",
                styles["body"],
            )
        )
    story.extend(
        [
            Spacer(1, 8),
            Paragraph("Management actions", styles["section"]),
        ]
    )
    for recommendation in executive_summary["recommendations"]:
        story.append(Paragraph(f"• {recommendation}", styles["body"]))
    story.extend(
        [
            Spacer(1, 8),
            _severity_table(serialized_findings),
            Spacer(1, 10),
            Paragraph("7.1 Target-wise vulnerability count", styles["section"]),
            _target_summary_table(grouped_by_asset),
            Spacer(1, 10),
            Paragraph("Key observations", styles["section"]),
        ]
    )

    for severity in ("critical", "high", "medium"):
        entries = grouped_by_severity.get(severity, [])
        if entries:
            story.append(
                Paragraph(
                    f"• {severity.title()} findings: {len(entries)}. Example: {entries[0].get('title')} on {entries[0].get('target')}.",
                    styles["body"],
                )
            )

    story.append(PageBreak())
    story.append(Paragraph("8. Detailed report", styles["title"]))
    for target_index, (target, entries) in enumerate(grouped_by_asset.items(), start=1):
        entries = sorted(entries, key=lambda item: (_severity_rank(item.get("severity")), item.get("cvss_score") or 0), reverse=True)
        story.append(Paragraph(f"{target_index}. Target: {target}", styles["section"]))
        story.append(Paragraph("Summary of findings", styles["subsection"]))
        story.append(_table(_finding_summary_rows(entries), [0.55 * inch, 3.35 * inch, 0.75 * inch, 0.55 * inch, 1.0 * inch]))
        open_port_rows = _open_port_rows(entries)
        if len(open_port_rows) > 1:
            story.append(Spacer(1, 6))
            story.append(Paragraph("Open port details", styles["subsection"]))
            story.append(_table(open_port_rows, [0.8 * inch, 0.8 * inch, 2.1 * inch, 2.3 * inch]))

        limit = len(entries) if normalized_mode == "technical" else min(len(entries), 6)
        for finding_index, item in enumerate(entries[:limit], start=1):
            story.append(Spacer(1, 8))
            story.append(Paragraph(f"{finding_index}. Vulnerability name: {item['title']}", styles["subsection"]))
            story.append(_detail_table(item))
            story.append(Paragraph("<b>Vulnerability description</b>", styles["body"]))
            story.append(Paragraph(item.get("evidence") or "No scanner narrative was stored for this finding.", styles["body"]))
            story.append(Paragraph("<b>Impact</b>", styles["body"]))
            story.append(
                Paragraph(
                    f"This issue is classified as {(item.get('severity') or 'info').title()} with CVSS {item.get('cvss_score') or 'n/a'}. "
                    "If left unresolved, it can increase the likelihood of compromise, disclosure, misuse, or operational disruption on the affected target.",
                    styles["body"],
                )
            )
            story.append(Paragraph("<b>Proof of concept / validation evidence</b>", styles["body"]))
            story.append(Paragraph(item.get("evidence") or "Direct validation output was not stored beyond the normalized finding evidence.", styles["body"]))
            story.append(Paragraph("<b>Remediation</b>", styles["body"]))
            story.append(
                Paragraph(
                    item.get("remediation")
                    or item.get("hardening_recommendation")
                    or "Review the exposed service, apply the vendor fix or configuration change, and validate the outcome with a re-test.",
                    styles["body"],
                )
            )
            refs = _reference_lines(item)
            if refs:
                story.append(Paragraph("<b>Reference links</b>", styles["body"]))
                for ref in refs:
                    story.append(Paragraph(f"• {ref}", styles["small"]))
            story.append(Paragraph(f"<b>Closure / verification state</b>: {item.get('verification_state') or 'pending'}", styles["body"]))

        story.append(PageBreak())

    story.append(Paragraph("9. Compliance impact and re-test guidance", styles["title"]))
    compliance_counts = Counter(tag for item in serialized_findings for tag in (item.get("compliance_map") or []))
    if compliance_counts:
        story.append(Paragraph("Compliance impact", styles["section"]))
        for tag, count in compliance_counts.most_common(15):
            story.append(Paragraph(f"• {tag}: {count} related finding(s)", styles["body"]))
    else:
        story.append(Paragraph("No compliance mappings were available for the current report scope.", styles["body"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Re-test guidance", styles["section"]))
    for line in [
        "Re-test each affected target after remediation is completed.",
        "Validate that the vulnerability is no longer reproducible and that the service matches the intended secure state.",
        "Capture screenshots, configuration outputs, patch evidence, or scanner proof for closure.",
        "Where a fix cannot be implemented immediately, document the compensating control, risk owner, and next review date.",
    ]:
        story.append(Paragraph(f"• {line}", styles["body"]))

    drawer = _header_drawer(header_name, header_logo_path)
    doc.build(story, onFirstPage=drawer, onLaterPages=drawer)
    return buffer.getvalue()
