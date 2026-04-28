import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from app.models.finding import Finding


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _serialize_finding(finding: Finding) -> dict:
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
        "target": _finding_target(finding),
        "evidence": finding.evidence,
    }


def _finding_target(finding: Finding) -> str:
    metadata = finding.finding_metadata or {}
    for key in ("target", "affected_url", "host", "hostname", "ip_address"):
        value = metadata.get(key)
        if value:
            return str(value)
    if finding.service:
        return f"{finding.service}:{finding.port}"
    return f"port {finding.port}"


def export_findings_json(findings: Iterable[Finding]) -> str:
    payload = [_serialize_finding(finding) for finding in findings]
    return json.dumps(payload, indent=2)


def export_findings_csv(findings: Iterable[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "title", "source", "severity", "status", "cvss_score", "cve_id", "compliance_map"])
    for finding in findings:
        writer.writerow(
            [
                str(finding.id),
                finding.title,
                finding.source,
                finding.severity,
                finding.status,
                finding.cvss_score,
                finding.cve_id,
                ", ".join(finding.compliance_map or []),
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


def _escape_pdf_text(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(value: str, width: int = 92) -> list[str]:
    words = str(value or "").replace("\r", " ").replace("\n", " ").split()
    if not words:
        return [""]
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _build_pdf(lines: list[str]) -> bytes:
    page_height = 792
    page_width = 612
    margin_left = 48
    top = 748
    max_lines_per_page = 48
    pages = [lines[index : index + max_lines_per_page] for index in range(0, len(lines), max_lines_per_page)] or [["No report data available."]]

    objects: list[str] = []
    page_object_numbers: list[int] = []
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append("")

    for page_lines in pages:
        content_lines = ["BT", "/F1 10 Tf", "13 TL", f"{margin_left} {top} Td"]
        for index, line in enumerate(page_lines):
            if index:
                content_lines.append("T*")
            content_lines.append(f"({_escape_pdf_text(line)}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines)
        content_object_number = len(objects) + 2
        page_object_number = len(objects) + 3
        page_object_numbers.append(page_object_number)
        objects.append(f"<< /Length {len(stream.encode('utf-8'))} >>\nstream\n{stream}\nendstream")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_width} {page_height}] "
            f"/Contents {content_object_number} 0 R /Resources << /Font << /F1 3 0 R >> >> >>"
        )

    objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_object_numbers)}] /Count {len(page_object_numbers)} >>"
    objects.insert(2, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    rendered = ["%PDF-1.4\n"]
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(sum(len(part.encode("utf-8")) for part in rendered))
        rendered.append(f"{number} 0 obj\n{body}\nendobj\n")
    xref_offset = sum(len(part.encode("utf-8")) for part in rendered)
    rendered.append(f"xref\n0 {len(objects) + 1}\n")
    rendered.append("0000000000 65535 f \n")
    for offset in offsets[1:]:
        rendered.append(f"{offset:010d} 00000 n \n")
    rendered.append(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF")
    return "".join(rendered).encode("utf-8")


def export_findings_pdf(findings: Iterable[Finding]) -> bytes:
    finding_list = list(findings)
    summary = summarize_findings(finding_list)
    lines = [
        "VAPTICOM Vulnerability Assessment Report",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "Executive Summary",
        f"Total findings identified: {summary['total_findings']}",
        f"Open findings requiring action: {summary['open_findings']}",
        "This report summarizes discovered vulnerabilities, affected targets, likely business impact, and recommended next actions.",
        "",
        "Severity breakdown:",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity.title()}: {summary['severity_counts'].get(severity, 0)}")

    lines.extend(["", "Recommended operating priorities:"])
    if summary["severity_counts"].get("critical", 0) or summary["severity_counts"].get("high", 0):
        lines.append("- Prioritize externally exposed critical and high findings first.")
        lines.append("- Assign owners, validate exploitability, and track remediation evidence.")
    else:
        lines.append("- Maintain monitoring, re-scan assets regularly, and close medium/low hardening gaps.")

    top_items = sorted(
        finding_list,
        key=lambda finding: ((finding.cvss_score or 0), SEVERITY_ORDER.get((finding.severity or "info").lower(), 0)),
        reverse=True,
    )[:20]
    lines.extend(["", "Top Findings"])
    if not top_items:
        lines.append("No findings are currently available for this report.")
    for index, finding in enumerate(top_items, start=1):
        serialized = _serialize_finding(finding)
        lines.extend(
            [
                "",
                f"{index}. {serialized['title']}",
                f"   Severity: {(serialized['severity'] or 'info').title()} | CVSS: {serialized['cvss_score'] or 'N/A'} | CVE: {serialized['cve_id'] or 'None mapped'}",
                f"   Target: {serialized['target']} | Source: {serialized['source']} | Status: {serialized['status']}",
            ]
        )
        remediation = serialized.get("remediation") or "Review the affected service, validate exposure, apply vendor guidance, and re-scan after remediation."
        for wrapped in _wrap_text(f"   Recommended action: {remediation}", 88):
            lines.append(wrapped)
        evidence = serialized.get("evidence")
        if evidence:
            for wrapped in _wrap_text(f"   Evidence: {evidence}", 88)[:3]:
                lines.append(wrapped)

    return _build_pdf(lines)
