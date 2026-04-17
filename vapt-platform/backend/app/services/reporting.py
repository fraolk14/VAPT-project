import csv
import io
import json
from collections import Counter
from typing import Iterable

from app.models.finding import Finding


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
    }


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
        key=lambda finding: ((finding.cvss_score or 0), 1 if (finding.severity or "").lower() == "critical" else 0),
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


def export_findings_pdf(findings: Iterable[Finding]) -> bytes:
    summary = summarize_findings(findings)
    lines = [
        "VAPT Platform Report",
        "",
        f"Total findings: {summary['total_findings']}",
        f"Open findings: {summary['open_findings']}",
        "",
        "Severity breakdown:",
    ]
    for severity, count in summary["severity_counts"].items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "Top findings:"])
    for finding in summary["top_findings"]:
        lines.append(f"- {finding['title']} | {finding['severity']} | {finding['source']} | {finding.get('cve_id') or 'No CVE'}")

    content = "\n".join(lines)
    pdf_body = f"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length {len(content) + 64} >> stream
BT
/F1 12 Tf
50 740 Td
({content.replace("(", "[").replace(")", "]").replace(chr(10), ") Tj T* (")}) Tj
ET
endstream
endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000063 00000 n 
0000000122 00000 n 
0000000248 00000 n 
0000000000 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
0
%%EOF"""
    return pdf_body.encode("utf-8")
