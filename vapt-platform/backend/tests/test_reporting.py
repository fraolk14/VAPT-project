import io
import unittest
import uuid
from datetime import datetime, timezone

from docx import Document

from app.models.finding import Finding
from app.services.reporting import build_report_preview, export_findings_docx


class ReportingTests(unittest.TestCase):
    def test_build_report_preview_contains_executive_summary_and_actions(self):
        finding = Finding(
            scan_id=uuid.uuid4(),
            title="Critical authentication bypass",
            category="web",
            source="openvas",
            port=443,
            protocol="tcp",
            service="https",
            state="open",
            severity="critical",
            cvss_score=9.8,
            evidence="A critical authentication bypass was reproduced.",
            remediation="Disable the vulnerable endpoint and rotate credentials.",
            compliance_map=["PCI DSS"],
            finding_metadata={"target": "app.internal"},
            detected_at=datetime.now(timezone.utc),
        )

        preview = build_report_preview([finding], mode="executive")

        self.assertEqual(preview["summary"]["total_findings"], 1)
        self.assertIn("executive_summary", preview)
        self.assertIn("recommendations", preview)
        self.assertEqual(preview["executive_summary"]["top_priority_findings"][0]["title"], "Critical authentication bypass")
        self.assertTrue(preview["recommendations"])

    def test_export_findings_docx_returns_document_bytes(self):
        finding = Finding(
            scan_id=uuid.uuid4(),
            title="Critical authentication bypass",
            category="web",
            source="openvas",
            port=443,
            protocol="tcp",
            service="https",
            state="open",
            severity="critical",
            cvss_score=9.8,
            evidence="A critical authentication bypass was reproduced.",
            remediation="Disable the vulnerable endpoint and rotate credentials.",
            compliance_map=["PCI DSS"],
            finding_metadata={"target": "app.internal"},
            detected_at=datetime.now(timezone.utc),
        )

        payload = export_findings_docx([finding], report_title="Executive report")
        document = Document(io.BytesIO(payload))
        paragraphs = [paragraph.text for paragraph in document.paragraphs]
        text = "\n".join(paragraphs)

        self.assertGreater(len(payload), 0)
        self.assertTrue(payload.startswith(b"PK"))
        self.assertIn("Executive summary", text)
        self.assertIn("Detailed report", text)
        self.assertIn("Compliance impact and re-test guidance", text)


if __name__ == "__main__":
    unittest.main()
