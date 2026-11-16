"""Report Studio: one report model, rendered as a live preview (JSON), PDF, DOCX, CSV or JSON.

The same `build_report_model` output drives the in-app preview and every export, so what the
analyst sees is what the client receives.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import defaultdict
from datetime import datetime, time, timezone
from pathlib import Path
from typing import Any
from uuid import UUID
from xml.sax.saxutils import escape

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.reporting import _control_mappings_for_finding, _finding_target, load_report_branding

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
SEV_CVSS = {"critical": "9.0 – 10.0", "high": "7.0 – 8.9", "medium": "4.0 – 6.9", "low": "0.1 – 3.9", "info": "0.0"}
ENGINE_NAMES = {
    "zap": "OWASP ZAP (web application scanning)",
    "web": "Built-in web checks",
    "nuclei": "Nuclei (template-based web detection)",
    "testssl": "testssl.sh (TLS testing)",
    "mobsf": "MobSF / static mobile analysis",
    "nmap": "Nmap (network service discovery)",
    "socket": "Socket probes (service checks)",
    "nmap+socket": "Nmap with socket probes (network)",
    "openvas": "Network engine",
    "endpoint-agent": "VAP endpoint agent",
}
MODES = {"executive", "technical", "compliance"}
CLASSIFICATIONS = {"Confidential", "Restricted", "Internal", "Public"}


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def _sev(value: str | None) -> str:
    s = str(value or "info").lower()
    return s if s in SEV_RANK else "info"


def _parse_date(value: str | None, end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value)[:10])
    except ValueError:
        return None
    return datetime.combine(d.date(), time.max if end else time.min, tzinfo=timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


_WEAK_TARGET = ("port ", "system inspection", "none", "unknown")


def _target_of(finding: Finding, assets: dict | None = None, scans: dict | None = None) -> str:
    """Best human-readable target for a finding.

    The legacy helper falls back to "port 0" / "<service>:0" when metadata lacks a host, which
    reads badly in a client report; prefer the app package, linked asset or the scan's target.
    """
    target = getattr(finding, "target", None)
    if target:
        return str(target)
    meta = finding.finding_metadata or {}
    candidate = _finding_target(finding)
    if candidate and not candidate.lower().startswith(_WEAK_TARGET) and not candidate.endswith(":0"):
        return candidate
    for key in ("package_name", "app_name", "file_name", "hostname", "device_hostname"):
        if meta.get(key):
            return str(meta[key])
    if assets and finding.asset_id in assets:
        return assets[finding.asset_id]
    if scans and finding.scan_id in scans:
        return scans[finding.scan_id]
    return candidate or "Unspecified target"


def _first_sentence(text: str | None, limit: int = 220) -> str:
    if not text:
        return ""
    clean = re.sub(r"\s+", " ", str(text)).strip()
    match = re.match(r"(.+?[.!?])(\s|$)", clean)
    sentence = match.group(1) if match else clean
    return sentence if len(sentence) <= limit else sentence[: limit - 1].rstrip() + "…"


_CONTROL_CHARS = re.compile("[" + "\x00-\x08\x0b\x0c\x0e-\x1f\x7f" + "]")


def _sanitize(value: Any) -> Any:
    """Strip control characters (raw service banners can contain binary bytes) from every string."""
    if isinstance(value, str):
        return _CONTROL_CHARS.sub("", value)
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    return value


def _clip(text: str | None, limit: int) -> str:
    clean = (str(text or "")).strip()
    return clean if len(clean) <= limit else clean[: limit - 1].rstrip() + "…"


def build_report_model(db: Session, request: dict[str, Any]) -> dict[str, Any]:
    mode = str(request.get("mode") or "executive").lower()
    mode = mode if mode in MODES else "executive"
    branding = load_report_branding()

    query = db.query(Finding)
    scan_info = None
    scan_id = request.get("scan_id")
    if scan_id and scan_id not in {"all", "latest"}:
        try:
            scan = db.get(Scan, UUID(str(scan_id)))
        except (ValueError, TypeError):
            scan = None
        if scan:
            query = query.filter(Finding.scan_id == scan.id)
            scan_info = {
                "id": str(scan.id),
                "name": scan.scan_name,
                "target": scan.target,
                "tool": scan.tool,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            }
    findings = query.all()
    from app.models.asset import Asset
    asset_ids = {f.asset_id for f in findings if f.asset_id}
    scan_ids = {f.scan_id for f in findings if f.scan_id}
    asset_names = {a.id: (a.hostname or a.asset_name or a.ip_address) for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()} if asset_ids else {}
    scan_targets = {sc.id: sc.target for sc in db.query(Scan).filter(Scan.id.in_(scan_ids)).all()} if scan_ids else {}
    target_for = lambda f: _target_of(f, asset_names, scan_targets)  # noqa: E731

    include_resolved = bool(request.get("include_resolved"))
    include_info = bool(request.get("include_info"))
    start = _parse_date(request.get("start_date"))
    end = _parse_date(request.get("end_date"), end=True)
    wanted_targets = {t.strip().lower() for t in (request.get("targets") or []) if t and t.strip()}

    selected: list[Finding] = []
    for f in findings:
        status = str(f.status or "open").lower()
        if status == "false_positive":
            continue  # analysts already rejected these
        if status == "resolved" and not include_resolved:
            continue
        if _sev(f.severity) == "info" and not include_info:
            continue
        detected = _as_utc(f.detected_at)
        if start and (not detected or detected < start):
            continue
        if end and (not detected or detected > end):
            continue
        if wanted_targets and target_for(f).lower() not in wanted_targets:
            continue
        selected.append(f)

    # Group per (issue title, target) so repeated hits read as one issue with occurrences.
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for f in selected:
        meta = f.finding_metadata or {}
        target = target_for(f)
        key = (f.title or "Untitled finding", target)
        sev = _sev(f.severity)
        g = groups.get(key)
        if not g:
            mapping = _control_mappings_for_finding(f)
            g = groups[key] = {
                "title": f.title or "Untitled finding",
                "target": target,
                "severity": sev,
                "cvss": float(f.cvss_score or 0),
                "cves": set(),
                "engines": set(),
                "occurrences": 0,
                "urls": [],
                "description": meta.get("description") or "",
                "evidence": f.evidence or "",
                "remediation": f.remediation or "",
                "references": [],
                "status": str(f.status or "open").lower(),
                "port": f.port if (f.port or 0) > 0 else None,
                "service": f.service,
                "first_seen": _as_utc(f.detected_at),
                "last_seen": _as_utc(f.detected_at),
                "controls": {"nist": mapping.get("nist") or [], "iso": mapping.get("iso") or []},
            }
        if SEV_RANK[sev] < SEV_RANK[g["severity"]]:
            g["severity"] = sev
        g["cvss"] = max(g["cvss"], float(f.cvss_score or 0))
        for cve in re.findall(r"CVE-\d{4}-\d{4,}", str(f.cve_id or ""), flags=re.I):
            g["cves"].add(cve.upper())
        if f.source:
            g["engines"].add(str(f.source))
        g["occurrences"] += int(meta.get("occurrences") or getattr(f, "duplicate_count", None) or 1)
        for url in (meta.get("affected_urls") or []) + ([meta.get("url")] if meta.get("url") else []):
            if url and url not in g["urls"]:
                g["urls"].append(url)
        refs = meta.get("references") or meta.get("reference") or []
        if isinstance(refs, str):
            refs = [r for r in re.split(r"\s+", refs) if r.startswith("http")]
        for ref in refs:
            if ref and ref not in g["references"]:
                g["references"].append(ref)
        seen = _as_utc(f.detected_at)
        if seen:
            g["first_seen"] = min(filter(None, [g["first_seen"], seen]))
            g["last_seen"] = max(filter(None, [g["last_seen"], seen]))

    issues = sorted(groups.values(), key=lambda g: (SEV_RANK[g["severity"]], -g["cvss"], g["title"].lower()))
    for index, g in enumerate(issues, start=1):
        g["id"] = f"VAPT-{index:03d}"
        g["cves"] = sorted(g["cves"])
        g["engines"] = sorted(g["engines"])
        g["urls"] = g["urls"][:25]
        g["references"] = g["references"][:6]
        g["description"] = _clip(g["description"] or g["evidence"].split(" | Evidence:")[0], 1400)
        g["evidence"] = _clip(g["evidence"], 1600)
        g["first_seen"] = g["first_seen"].isoformat() if g["first_seen"] else None
        g["last_seen"] = g["last_seen"].isoformat() if g["last_seen"] else None

    counts = {s: sum(1 for g in issues if g["severity"] == s) for s in SEV_ORDER}
    targets: dict[str, dict[str, Any]] = {}
    for g in issues:
        t = targets.setdefault(g["target"], {"target": g["target"], "issues": 0, "highest": "info", "counts": {s: 0 for s in SEV_ORDER}})
        t["issues"] += 1
        t["counts"][g["severity"]] += 1
        if SEV_RANK[g["severity"]] < SEV_RANK[t["highest"]]:
            t["highest"] = g["severity"]
    target_list = sorted(targets.values(), key=lambda t: (SEV_RANK[t["highest"]], -t["issues"], t["target"]))

    if counts["critical"]:
        rating = "Critical"
    elif counts["high"]:
        rating = "High"
    elif counts["medium"]:
        rating = "Medium"
    elif counts["low"]:
        rating = "Low"
    else:
        rating = "None identified"

    stamps = [datetime.fromisoformat(g["first_seen"]) for g in issues if g["first_seen"]] + [
        datetime.fromisoformat(g["last_seen"]) for g in issues if g["last_seen"]
    ]
    period_start = start or (min(stamps) if stamps else None)
    period_end = end or (max(stamps) if stamps else None)
    engines = sorted({e for g in issues for e in g["engines"]})

    urgent = counts["critical"] + counts["high"]
    if issues:
        narrative = (
            f"This assessment identified {len(issues)} distinct security issue{'s' if len(issues) != 1 else ''} "
            f"across {len(target_list)} target{'s' if len(target_list) != 1 else ''}. "
            + (
                f"{urgent} {'is' if urgent == 1 else 'are'} rated critical or high and should be remediated as a priority. "
                if urgent
                else "None are rated critical or high. "
            )
            + f"The overall risk rating for the assessed scope is {rating.upper()}, based on the most severe open issue."
        )
    else:
        narrative = "No open security issues were identified within the selected scope and filters."

    recommendations = []
    for g in issues[:5]:
        if g["severity"] in {"critical", "high", "medium"}:
            recommendations.append({
                "id": g["id"],
                "severity": g["severity"],
                "title": g["title"],
                "target": g["target"],
                "action": _first_sentence(g["remediation"]) or "Review and remediate this issue.",
            })

    # Indicative control mapping (NIST SP 800-53 Rev. 5 / ISO/IEC 27001:2022 Annex A).
    control_index: dict[str, dict[str, dict[str, Any]]] = {"nist": {}, "iso": {}}
    for g in issues:
        for fw in ("nist", "iso"):
            for control in g["controls"][fw]:
                entry = control_index[fw].setdefault(control, {"control": control, "issues": [], "highest": "info", "targets": set()})
                entry["issues"].append(g["id"])
                entry["targets"].add(g["target"])
                if SEV_RANK[g["severity"]] < SEV_RANK[entry["highest"]]:
                    entry["highest"] = g["severity"]
    compliance = {
        fw: sorted(
            [{**v, "targets": sorted(v["targets"])} for v in control_index[fw].values()],
            key=lambda v: (SEV_RANK[v["highest"]], -len(v["issues"]), v["control"]),
        )
        for fw in control_index
    }

    issues = _sanitize(issues)
    target_list = _sanitize(target_list)
    now = datetime.now(timezone.utc)
    classification = request.get("classification") if request.get("classification") in CLASSIFICATIONS else "Confidential"
    default_titles = {
        "executive": "Vulnerability Assessment — Executive Report",
        "technical": "Vulnerability Assessment — Technical Report",
        "compliance": "Vulnerability Assessment — Compliance Report",
    }
    return _sanitize({
        "mode": mode,
        "options": {
            "include_cves": request.get("include_cves", True) is not False,
            "include_remediation": request.get("include_remediation", True) is not False,
            "include_evidence": request.get("include_evidence", True) is not False,
            "include_compliance": mode == "compliance" or request.get("include_compliance", True) is not False,
            "include_details": mode == "technical" or bool(request.get("include_details")),
            "include_resolved": include_resolved,
            "include_info": include_info,
        },
        "meta": {
            "title": _clip(request.get("report_title") or default_titles[mode], 160),
            "organization": _clip(request.get("company_name") or branding["company_name"], 120),
            "prepared_for": _clip(request.get("prepared_for") or "", 120),
            "author": _clip(request.get("author_name") or "Security Assessment Team", 120),
            "classification": classification,
            "version": _clip(request.get("version") or "1.0", 20),
            "generated_at": now.isoformat(),
            "period_start": period_start.isoformat() if period_start else None,
            "period_end": period_end.isoformat() if period_end else None,
            "has_logo": bool(branding.get("logo_path") and Path(branding["logo_path"]).exists()),
        },
        "scan": scan_info,
        "summary": {
            "rating": rating,
            "issues": len(issues),
            "findings": len(selected),
            "targets": len(target_list),
            "counts": counts,
            "narrative": narrative,
            "engines": [ENGINE_NAMES.get(e.lower(), e) for e in engines],
        },
        "recommendations": recommendations,
        "targets": target_list,
        "issues": issues,
        "compliance": compliance,
        "limitations": [
            "Testing was automated and unauthenticated: functionality behind a login was not assessed.",
            "Results reflect the state of each target at the time it was scanned.",
            "Automated tools can report false positives; issues analysts marked as false positives are excluded.",
            "Compliance mappings are indicative, derived from finding types; they are not an audit attestation.",
        ],
    })


# ---------------------------------------------------------------------------
# CSV / JSON
# ---------------------------------------------------------------------------

def render_csv(model: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ID", "Issue", "Target", "Severity", "CVSS", "CVEs", "Occurrences", "Status", "Engines", "First seen", "Last seen", "Remediation"])
    for g in model["issues"]:
        writer.writerow([
            g["id"], g["title"], g["target"], SEV_LABEL[g["severity"]], f"{g['cvss']:.1f}" if g["cvss"] else "",
            " ".join(g["cves"]), g["occurrences"], g["status"], " ".join(g["engines"]),
            g["first_seen"] or "", g["last_seen"] or "", g["remediation"],
        ])
    return buffer.getvalue().encode("utf-8-sig")


def render_json(model: dict[str, Any]) -> bytes:
    return json.dumps(model, indent=2, default=str).encode("utf-8")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _fmt_date(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y")
    except ValueError:
        return value


def _period(meta: dict[str, Any]) -> str:
    if meta["period_start"] and meta["period_end"]:
        return f"{_fmt_date(meta['period_start'])} – {_fmt_date(meta['period_end'])}"
    return "—"


def render_pdf(model: dict[str, Any], logo_path: str | None = None) -> bytes:
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (
        CondPageBreak, Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    NAVY = colors.HexColor("#0B1F3A")
    ACCENT = colors.HexColor("#1F6FEB")
    INK = colors.HexColor("#1D2939")
    MUTED = colors.HexColor("#667085")
    LINE = colors.HexColor("#D0D5DD")
    SOFT = colors.HexColor("#F2F4F7")
    SEV = {
        "critical": (colors.HexColor("#B42318"), colors.HexColor("#FEE4E2")),
        "high": (colors.HexColor("#C4320A"), colors.HexColor("#FFE6D5")),
        "medium": (colors.HexColor("#B54708"), colors.HexColor("#FEF0C7")),
        "low": (colors.HexColor("#475467"), colors.HexColor("#EAECF0")),
        "info": (colors.HexColor("#667085"), colors.HexColor("#F2F4F7")),
    }

    meta, summary, opts = model["meta"], model["summary"], model["options"]
    e = lambda v: escape(str(v if v is not None else ""))  # noqa: E731

    base = dict(fontName="Helvetica", textColor=INK)
    st = {
        "body": ParagraphStyle("body", fontSize=9.5, leading=14, spaceAfter=6, **base),
        "small": ParagraphStyle("small", fontSize=8, leading=11, textColor=MUTED, fontName="Helvetica"),
        "cell": ParagraphStyle("cell", fontSize=8.5, leading=11, **base),
        "cellb": ParagraphStyle("cellb", fontSize=8.5, leading=11, fontName="Helvetica-Bold", textColor=INK),
        "head": ParagraphStyle("head", fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=colors.white),
        "h1": ParagraphStyle("h1", fontSize=17, leading=22, fontName="Helvetica-Bold", textColor=NAVY, spaceBefore=4, spaceAfter=10),
        "h2": ParagraphStyle("h2", fontSize=12, leading=16, fontName="Helvetica-Bold", textColor=NAVY, spaceBefore=10, spaceAfter=6),
        "label": ParagraphStyle("label", fontSize=7.5, leading=10, fontName="Helvetica-Bold", textColor=MUTED, spaceBefore=6),
        "mono": ParagraphStyle("mono", fontSize=7.5, leading=10, fontName="Courier", textColor=INK, backColor=SOFT, borderPadding=6, spaceBefore=9, spaceAfter=10),
        "cover_title": ParagraphStyle("ct", fontSize=26, leading=32, fontName="Helvetica-Bold", textColor=NAVY, spaceAfter=10),
        "cover_sub": ParagraphStyle("cs", fontSize=12, leading=17, textColor=MUTED, fontName="Helvetica"),
    }

    def table(rows, widths, header=True, zebra=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), NAVY)]
        if zebra:
            for r in range(1 if header else 0, len(rows)):
                if r % 2 == 0:
                    style.append(("BACKGROUND", (0, r), (-1, r), SOFT))
        t.setStyle(TableStyle(style))
        return t

    def sev_chip(sev):
        fg, bg = SEV[sev]
        t = Table([[Paragraph(f'<font color="{fg.hexval().replace("0x", "#")}"><b>{SEV_LABEL[sev]}</b></font>', st["cell"])]])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        return t

    def severity_chart():
        width, row_h = 160 * mm, 16
        d = Drawing(width, row_h * 5 + 6)
        peak = max(1, max(summary["counts"].values()))
        for i, sev in enumerate(SEV_ORDER):
            y = (4 - i) * row_h + 4
            d.add(String(0, y + 3, SEV_LABEL[sev], fontName="Helvetica", fontSize=8, fillColor=INK))
            d.add(Rect(70, y, width - 110, 10, fillColor=SOFT, strokeColor=None))
            n = summary["counts"][sev]
            if n:
                d.add(Rect(70, y, (width - 110) * n / peak, 10, fillColor=SEV[sev][0], strokeColor=None))
            d.add(String(width - 32, y + 2, str(n), fontName="Helvetica-Bold", fontSize=9, fillColor=INK))
        return d

    logo = None
    if logo_path and Path(logo_path).exists() and Path(logo_path).suffix.lower() in {".png", ".jpg", ".jpeg"}:
        try:
            from reportlab.lib.utils import ImageReader
            iw, ih = ImageReader(logo_path).getSize()
            scale = min(46 * mm / iw, 18 * mm / ih)
            logo = (logo_path, iw * scale, ih * scale)
        except Exception:
            logo = None

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            w, h = A4
            page = self._pageNumber
            if page == 1:
                self.setFillColor(NAVY)
                self.rect(0, h - 14 * mm, w, 14 * mm, stroke=0, fill=1)
                self.setFillColor(ACCENT)
                self.rect(0, h - 15.2 * mm, w, 1.2 * mm, stroke=0, fill=1)
                self.setFillColor(colors.white)
                self.setFont("Helvetica-Bold", 9)
                self.drawString(18 * mm, h - 9 * mm, meta["classification"].upper())
                self.setFillColor(MUTED)
                self.setFont("Helvetica", 7.5)
                self.drawString(18 * mm, 12 * mm, f"{meta['classification']} — prepared by {meta['organization']}. Do not distribute without permission.")
                return
            self.setStrokeColor(LINE)
            self.setLineWidth(0.5)
            self.line(18 * mm, h - 16 * mm, w - 18 * mm, h - 16 * mm)
            self.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(NAVY)
            self.drawString(18 * mm, h - 13 * mm, meta["organization"][:60])
            self.setFont("Helvetica", 8)
            self.setFillColor(MUTED)
            self.drawRightString(w - 18 * mm, h - 13 * mm, meta["title"][:80])
            self.drawString(18 * mm, 10 * mm, meta["classification"].upper())
            self.drawRightString(w - 18 * mm, 10 * mm, f"Page {page} of {total}")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=22 * mm, bottomMargin=22 * mm,
        title=meta["title"], author=meta["author"], subject="Vulnerability assessment report", creator="VAPTICOM",
    )
    W = A4[0] - 36 * mm
    story: list[Any] = []

    # ---- Cover ----
    story.append(Spacer(1, 22 * mm))
    if logo:
        story.append(Image(logo[0], width=logo[1], height=logo[2], hAlign="LEFT"))
        story.append(Spacer(1, 12 * mm))
    story.append(Paragraph(e(meta["title"]), st["cover_title"]))
    if meta["prepared_for"]:
        story.append(Paragraph(f"Prepared for <b>{e(meta['prepared_for'])}</b>", st["cover_sub"]))
    story.append(Paragraph(f"Prepared by {e(meta['organization'])}", st["cover_sub"]))
    story.append(Spacer(1, 16 * mm))
    cover_rows = [
        [Paragraph("<b>Report type</b>", st["cell"]), Paragraph(e(model["mode"].title()), st["cell"])],
        [Paragraph("<b>Assessment period</b>", st["cell"]), Paragraph(e(_period(meta)), st["cell"])],
        [Paragraph("<b>Overall risk</b>", st["cell"]), Paragraph(f"<b>{e(summary['rating'])}</b>", st["cell"])],
        [Paragraph("<b>Author</b>", st["cell"]), Paragraph(e(meta["author"]), st["cell"])],
        [Paragraph("<b>Version / date</b>", st["cell"]), Paragraph(f"{e(meta['version'])} · {_fmt_date(meta['generated_at'])}", st["cell"])],
    ]
    story.append(table(cover_rows, [45 * mm, W - 45 * mm], header=False, zebra=False))
    story.append(PageBreak())

    # ---- Document control ----
    story.append(Paragraph("Document control", st["h1"]))
    story.append(table([
        [Paragraph("Field", st["head"]), Paragraph("Value", st["head"])],
        [Paragraph("Title", st["cell"]), Paragraph(e(meta["title"]), st["cell"])],
        [Paragraph("Prepared for", st["cell"]), Paragraph(e(meta["prepared_for"] or "—"), st["cell"])],
        [Paragraph("Prepared by", st["cell"]), Paragraph(f"{e(meta['author'])}, {e(meta['organization'])}", st["cell"])],
        [Paragraph("Classification", st["cell"]), Paragraph(e(meta["classification"]), st["cell"])],
        [Paragraph("Version", st["cell"]), Paragraph(e(meta["version"]), st["cell"])],
        [Paragraph("Generated", st["cell"]), Paragraph(_fmt_date(meta["generated_at"]), st["cell"])],
    ], [45 * mm, W - 45 * mm]))
    story.append(Spacer(1, 6 * mm))

    # ---- Executive summary ----
    story.append(Paragraph("1. Executive summary", st["h1"]))
    fg, bg = SEV.get(summary["rating"].lower(), (NAVY, SOFT))
    rating_box = Table([[Paragraph("OVERALL RISK", st["small"]), Paragraph(f'<font size="16" color="{fg.hexval().replace("0x", "#")}"><b>{e(summary["rating"].upper())}</b></font>', st["body"])]], colWidths=[35 * mm, W - 35 * mm])
    rating_box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(rating_box)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(e(summary["narrative"]), st["body"]))
    kpi = [[Paragraph(f'<font size="15"><b>{v}</b></font><br/><font size="7.5" color="#667085">{k}</font>', st["cell"]) for k, v in [
        ("ISSUES", summary["issues"]), ("TARGETS", summary["targets"]),
        ("CRITICAL", summary["counts"]["critical"]), ("HIGH", summary["counts"]["high"]), ("MEDIUM", summary["counts"]["medium"]),
    ]]]
    kt = Table(kpi, colWidths=[W / 5] * 5)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    story.append(kt)
    story.append(Paragraph("Issues by severity", st["h2"]))
    story.append(severity_chart())

    if model["recommendations"]:
        story.append(Paragraph("Priority recommendations", st["h2"]))
        rows = [[Paragraph(h, st["head"]) for h in ("ID", "Issue", "Severity", "Recommended action" if opts["include_remediation"] else "Target")]]
        for r in model["recommendations"]:
            rows.append([
                Paragraph(e(r["id"]), st["cellb"]),
                Paragraph(f"{e(r['title'])}<br/><font color='#667085' size='7.5'>{e(r['target'])}</font>", st["cell"]),
                sev_chip(r["severity"]),
                Paragraph(e(r["action"] if opts["include_remediation"] else r["target"]), st["cell"]),
            ])
        story.append(table(rows, [21 * mm, 61 * mm, 24 * mm, W - 106 * mm]))

    # ---- Scope ----
    story.append(CondPageBreak(90 * mm))
    story.append(Paragraph("2. Scope and methodology", st["h1"]))
    scope_text = f"Assessment window: <b>{e(_period(meta))}</b>."
    if model["scan"]:
        scope_text += f" Scope limited to scan <b>{e(model['scan']['name'])}</b> ({e(model['scan']['target'])})."
    story.append(Paragraph(scope_text, st["body"]))
    if summary["engines"]:
        story.append(Paragraph("Tools used: " + e(", ".join(summary["engines"])) + ".", st["body"]))
    rows = [[Paragraph(h, st["head"]) for h in ("Target", "Issues", "Critical", "High", "Medium", "Low", "Highest")]]
    for t in model["targets"][:60]:
        rows.append([Paragraph(e(t["target"]), st["cell"]), str(t["issues"]), str(t["counts"]["critical"]), str(t["counts"]["high"]), str(t["counts"]["medium"]), str(t["counts"]["low"]), sev_chip(t["highest"])])
    if len(rows) > 1:
        story.append(table(rows, [W - 120 * mm, 16 * mm, 16 * mm, 16 * mm, 16 * mm, 16 * mm, 40 * mm]))
    story.append(Paragraph("Limitations", st["h2"]))
    for item in model["limitations"]:
        story.append(Paragraph(f"• {e(item)}", st["body"]))

    # ---- Findings summary ----
    story.append(CondPageBreak(90 * mm))
    story.append(Paragraph("3. Findings summary", st["h1"]))
    if model["issues"]:
        head = ["ID", "Issue", "Target", "Severity", "CVSS"] + (["CVE"] if opts["include_cves"] else [])
        rows = [[Paragraph(h, st["head"]) for h in head]]
        for g in model["issues"]:
            row = [
                Paragraph(e(g["id"]), st["cellb"]), Paragraph(e(g["title"]), st["cell"]), Paragraph(e(g["target"]), st["cell"]),
                sev_chip(g["severity"]), Paragraph(f"{g['cvss']:.1f}" if g["cvss"] else "—", st["cell"]),
            ]
            if opts["include_cves"]:
                row.append(Paragraph(e(", ".join(g["cves"][:2]) or "—"), st["cell"]))
            rows.append(row)
        widths = [21 * mm, 56 * mm, 38 * mm, 24 * mm, 13 * mm] + ([W - 152 * mm] if opts["include_cves"] else [])
        if not opts["include_cves"]:
            widths[1] += W - 152 * mm
        story.append(table(rows, widths))
    else:
        story.append(Paragraph("No issues in the selected scope.", st["body"]))

    section = 4
    # ---- Detailed findings ----
    if opts["include_details"] and model["issues"]:
        story.append(PageBreak())
        story.append(Paragraph(f"{section}. Detailed findings", st["h1"]))
        section += 1
        for g in model["issues"]:
            block = [Paragraph(f"{e(g['id'])} · {e(g['title'])}", st["h2"])]
            facts = [
                [Paragraph("<b>Severity</b>", st["cell"]), sev_chip(g["severity"]), Paragraph("<b>CVSS</b>", st["cell"]), Paragraph(f"{g['cvss']:.1f}" if g["cvss"] else "—", st["cell"])],
                [Paragraph("<b>Target</b>", st["cell"]), Paragraph(e(g["target"]), st["cell"]), Paragraph("<b>Occurrences</b>", st["cell"]), Paragraph(str(g["occurrences"]), st["cell"])],
                [Paragraph("<b>Detected by</b>", st["cell"]), Paragraph(e(", ".join(g["engines"]) or "—"), st["cell"]), Paragraph("<b>Status</b>", st["cell"]), Paragraph(e(g["status"].replace("_", " ").title()), st["cell"])],
            ]
            if opts["include_cves"] and g["cves"]:
                facts.append([Paragraph("<b>CVE</b>", st["cell"]), Paragraph(e(", ".join(g["cves"])), st["cell"]), "", ""])
            ft = table(facts, [24 * mm, W / 2 - 24 * mm, 26 * mm, W / 2 - 26 * mm], header=False, zebra=False)
            block.append(ft)
            block.append(Paragraph("DESCRIPTION", st["label"]))
            block.append(Paragraph(e(g["description"] or "No description provided by the scanner."), st["body"]))
            story.append(KeepTogether(block))
            if opts["include_evidence"] and g["evidence"]:
                story.append(Paragraph("EVIDENCE", st["label"]))
                story.append(Paragraph(e(g["evidence"]).replace("\n", "<br/>"), st["mono"]))
            if g["urls"]:
                story.append(Paragraph("AFFECTED LOCATIONS", st["label"]))
                more = f" … and {g['occurrences'] - len(g['urls'][:10])} more" if g["occurrences"] > len(g["urls"][:10]) and len(g["urls"]) > 10 else ""
                story.append(Paragraph(e(", ".join(g["urls"][:10])) + e(more), st["small"]))
            if opts["include_remediation"]:
                story.append(Paragraph("REMEDIATION", st["label"]))
                story.append(Paragraph(e(g["remediation"] or "No remediation guidance provided by the scanner."), st["body"]))
            if opts["include_compliance"]:
                story.append(Paragraph(
                    f"<font color='#667085'>Controls: NIST {e(', '.join(g['controls']['nist']))} · ISO 27001 {e(', '.join(g['controls']['iso']))}</font>",
                    st["small"],
                ))
            if g["references"]:
                story.append(Paragraph("<font color='#667085'>References: " + e(" ".join(g["references"][:3])) + "</font>", st["small"]))
            story.append(Spacer(1, 6 * mm))

    # ---- Compliance ----
    if opts["include_compliance"] and model["issues"]:
        story.append(PageBreak())
        story.append(Paragraph(f"{section}. Control mapping", st["h1"]))
        section += 1
        story.append(Paragraph(
            "Findings are mapped to controls by finding type. This mapping is indicative and supports "
            "remediation planning; it is not a formal compliance audit or attestation.",
            st["body"],
        ))
        for fw, label in (("nist", "NIST SP 800-53 Rev. 5"), ("iso", "ISO/IEC 27001:2022 Annex A")):
            story.append(Paragraph(label, st["h2"]))
            rows = [[Paragraph(h, st["head"]) for h in ("Control", "Highest severity", "Related issues", "Targets")]]
            for c in model["compliance"][fw]:
                rows.append([
                    Paragraph(f"<b>{e(c['control'])}</b>", st["cell"]), sev_chip(c["highest"]),
                    Paragraph(e(", ".join(c["issues"][:12]) + (" …" if len(c["issues"]) > 12 else "")), st["cell"]),
                    Paragraph(str(len(c["targets"])), st["cell"]),
                ])
            story.append(table(rows, [26 * mm, 30 * mm, W - 78 * mm, 22 * mm]))

    # ---- Appendix ----
    story.append(PageBreak())
    story.append(Paragraph(f"Appendix A. Risk rating method", st["h1"]))
    story.append(Paragraph("Each issue is rated by the scanner's severity, aligned with CVSS v3 score bands. The overall risk equals the most severe open issue in scope.", st["body"]))
    rows = [[Paragraph(h, st["head"]) for h in ("Rating", "CVSS range", "Meaning")]]
    meaning = {
        "critical": "Likely to be exploited with severe impact. Fix immediately.",
        "high": "Serious weakness. Fix as a priority.",
        "medium": "Exploitable under some conditions. Fix in the normal cycle.",
        "low": "Limited impact. Fix when convenient.",
        "info": "No direct risk; noted for awareness.",
    }
    for s in SEV_ORDER:
        rows.append([sev_chip(s), Paragraph(SEV_CVSS[s], st["cell"]), Paragraph(meaning[s], st["cell"])])
    story.append(table(rows, [32 * mm, 30 * mm, W - 62 * mm]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# DOCX
# ---------------------------------------------------------------------------

def render_docx(model: dict[str, Any], logo_path: str | None = None) -> bytes:
    from docx import Document
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Mm, Pt, RGBColor

    meta, summary, opts = model["meta"], model["summary"], model["options"]
    navy = RGBColor(0x0B, 0x1F, 0x3A)
    sev_rgb = {"critical": "B42318", "high": "C4320A", "medium": "B54708", "low": "475467", "info": "667085"}

    doc = Document()
    for section in doc.sections:
        section.page_height, section.page_width = Mm(297), Mm(210)
        section.left_margin = section.right_margin = Mm(18)
        section.top_margin = section.bottom_margin = Mm(20)
    styles = doc.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10)

    def shade(cell, hex_fill):
        tc_pr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), hex_fill)
        tc_pr.append(shd)

    def heading(text, level=1):
        h = doc.add_heading(text, level=level)
        for run in h.runs:
            run.font.color.rgb = navy
        return h

    def grid(rows, header=True):
        # Add rows one at a time and use row.cells: table.cell(r, c) is O(rows) per call,
        # which made a 177-row findings table take ~40 seconds.
        t = doc.add_table(rows=0, cols=len(rows[0]))
        t.style = "Table Grid"
        for r, row in enumerate(rows):
            cells = t.add_row().cells
            for c, value in enumerate(row):
                cell = cells[c]
                cell.text = str(value)
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(8.5)
                        if header and r == 0:
                            run.font.bold = True
                            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                if header and r == 0:
                    shade(cell, "0B1F3A")
        return t

    # Header / footer
    sec = doc.sections[0]
    sec.different_first_page_header_footer = True
    hp = sec.header.paragraphs[0]
    hp.text = f"{meta['organization']} — {meta['title']}"
    hp.runs[0].font.size = Pt(8)
    fp = sec.footer.paragraphs[0]
    fp.text = f"{meta['classification'].upper()} · Generated {_fmt_date(meta['generated_at'])}"
    fp.runs[0].font.size = Pt(8)

    # Cover
    doc.add_paragraph().add_run(meta["classification"].upper()).bold = True
    if logo_path and Path(logo_path).exists() and Path(logo_path).suffix.lower() in {".png", ".jpg", ".jpeg"}:
        try:
            doc.add_picture(logo_path, height=Mm(18))
        except Exception:
            pass
    title = doc.add_paragraph()
    run = title.add_run(meta["title"])
    run.bold, run.font.size, run.font.color.rgb = True, Pt(24), navy
    if meta["prepared_for"]:
        doc.add_paragraph(f"Prepared for {meta['prepared_for']}")
    doc.add_paragraph(f"Prepared by {meta['organization']}")
    grid([
        ["Report type", model["mode"].title()],
        ["Assessment period", _period(meta)],
        ["Overall risk", summary["rating"]],
        ["Author", meta["author"]],
        ["Version / date", f"{meta['version']} · {_fmt_date(meta['generated_at'])}"],
    ], header=False)
    doc.add_page_break()

    heading("Document control")
    grid([["Field", "Value"], ["Title", meta["title"]], ["Prepared for", meta["prepared_for"] or "—"],
          ["Prepared by", f"{meta['author']}, {meta['organization']}"], ["Classification", meta["classification"]],
          ["Version", meta["version"]], ["Generated", _fmt_date(meta["generated_at"])]])

    heading("1. Executive summary")
    p = doc.add_paragraph()
    r = p.add_run(f"Overall risk: {summary['rating'].upper()}")
    r.bold = True
    r.font.color.rgb = RGBColor.from_string(sev_rgb.get(summary["rating"].lower(), "0B1F3A"))
    doc.add_paragraph(summary["narrative"])
    grid([["Issues", "Targets", "Critical", "High", "Medium", "Low"],
          [summary["issues"], summary["targets"], summary["counts"]["critical"], summary["counts"]["high"], summary["counts"]["medium"], summary["counts"]["low"]]])
    if model["recommendations"]:
        heading("Priority recommendations", 2)
        rows = [["ID", "Issue", "Severity", "Recommended action" if opts["include_remediation"] else "Target"]]
        rows += [[r["id"], f"{r['title']} ({r['target']})", SEV_LABEL[r["severity"]], r["action"] if opts["include_remediation"] else r["target"]] for r in model["recommendations"]]
        grid(rows)

    doc.add_page_break()
    heading("2. Scope and methodology")
    scope = f"Assessment window: {_period(meta)}."
    if model["scan"]:
        scope += f" Scope limited to scan {model['scan']['name']} ({model['scan']['target']})."
    doc.add_paragraph(scope)
    if summary["engines"]:
        doc.add_paragraph("Tools used: " + ", ".join(summary["engines"]) + ".")
    if model["targets"]:
        rows = [["Target", "Issues", "Critical", "High", "Medium", "Low", "Highest"]]
        rows += [[t["target"], t["issues"], t["counts"]["critical"], t["counts"]["high"], t["counts"]["medium"], t["counts"]["low"], SEV_LABEL[t["highest"]]] for t in model["targets"][:60]]
        grid(rows)
    heading("Limitations", 2)
    for item in model["limitations"]:
        doc.add_paragraph(item, style="List Bullet")

    doc.add_page_break()
    heading("3. Findings summary")
    if model["issues"]:
        head = ["ID", "Issue", "Target", "Severity", "CVSS"] + (["CVE"] if opts["include_cves"] else [])
        rows = [head]
        for g in model["issues"]:
            row = [g["id"], g["title"], g["target"], SEV_LABEL[g["severity"]], f"{g['cvss']:.1f}" if g["cvss"] else "—"]
            if opts["include_cves"]:
                row.append(", ".join(g["cves"][:2]) or "—")
            rows.append(row)
        grid(rows)
    else:
        doc.add_paragraph("No issues in the selected scope.")

    section_no = 4
    if opts["include_details"] and model["issues"]:
        doc.add_page_break()
        heading(f"{section_no}. Detailed findings")
        section_no += 1
        for g in model["issues"]:
            heading(f"{g['id']} · {g['title']}", 2)
            facts = [["Severity", SEV_LABEL[g["severity"]], "CVSS", f"{g['cvss']:.1f}" if g["cvss"] else "—"],
                     ["Target", g["target"], "Occurrences", g["occurrences"]],
                     ["Detected by", ", ".join(g["engines"]) or "—", "Status", g["status"].replace("_", " ").title()]]
            if opts["include_cves"] and g["cves"]:
                facts.append(["CVE", ", ".join(g["cves"]), "", ""])
            grid(facts, header=False)
            doc.add_paragraph().add_run("Description").bold = True
            doc.add_paragraph(g["description"] or "No description provided by the scanner.")
            if opts["include_evidence"] and g["evidence"]:
                doc.add_paragraph().add_run("Evidence").bold = True
                ev = doc.add_paragraph()
                er = ev.add_run(g["evidence"])
                er.font.name, er.font.size = "Consolas", Pt(8)
            if g["urls"]:
                doc.add_paragraph().add_run("Affected locations").bold = True
                doc.add_paragraph(", ".join(g["urls"][:10]))
            if opts["include_remediation"]:
                doc.add_paragraph().add_run("Remediation").bold = True
                doc.add_paragraph(g["remediation"] or "No remediation guidance provided by the scanner.")
            if opts["include_compliance"]:
                doc.add_paragraph(f"Controls: NIST {', '.join(g['controls']['nist'])} · ISO 27001 {', '.join(g['controls']['iso'])}")

    if opts["include_compliance"] and model["issues"]:
        doc.add_page_break()
        heading(f"{section_no}. Control mapping")
        doc.add_paragraph("Findings are mapped to controls by finding type. This mapping is indicative and supports remediation planning; it is not a formal compliance audit or attestation.")
        for fw, label in (("nist", "NIST SP 800-53 Rev. 5"), ("iso", "ISO/IEC 27001:2022 Annex A")):
            heading(label, 2)
            rows = [["Control", "Highest severity", "Related issues", "Targets"]]
            rows += [[c["control"], SEV_LABEL[c["highest"]], ", ".join(c["issues"][:12]), len(c["targets"])] for c in model["compliance"][fw]]
            grid(rows)

    doc.add_page_break()
    heading("Appendix A. Risk rating method")
    doc.add_paragraph("Each issue is rated by the scanner's severity, aligned with CVSS v3 score bands. The overall risk equals the most severe open issue in scope.")
    grid([["Rating", "CVSS range"]] + [[SEV_LABEL[s], SEV_CVSS[s]] for s in SEV_ORDER])

    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()
