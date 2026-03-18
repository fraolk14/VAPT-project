import csv
import io
import json
from typing import Iterable

from app.models.finding import Finding


def export_findings_json(findings: Iterable[Finding]) -> str:
    payload = []
    for finding in findings:
        payload.append(
            {
                "id": str(finding.id),
                "title": finding.title,
                "source": finding.source,
                "severity": finding.severity,
                "status": finding.status,
                "cvss_score": finding.cvss_score,
            }
        )
    return json.dumps(payload, indent=2)


def export_findings_csv(findings: Iterable[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "title", "source", "severity", "status", "cvss_score"])
    for finding in findings:
        writer.writerow(
            [
                str(finding.id),
                finding.title,
                finding.source,
                finding.severity,
                finding.status,
                finding.cvss_score,
            ]
        )
    return buffer.getvalue()
