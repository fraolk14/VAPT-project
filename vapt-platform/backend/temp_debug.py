from app.services.reporting import export_findings_docx
from app.models.finding import Finding
import uuid
from datetime import datetime, timezone
from docx import Document
import io

finding = Finding(scan_id=uuid.uuid4(), title='Test', category='web', source='openvas', port=443, protocol='tcp', service='https', state='open', severity='critical', cvss_score=9.8, evidence='x', remediation='y', compliance_map=['PCI DSS'], finding_metadata={'target':'app.internal'}, detected_at=datetime.now(timezone.utc))
payload = export_findings_docx([finding], report_title='Executive report')
doc = Document(io.BytesIO(payload))
for i, table in enumerate(doc.tables):
    print('TABLE', i)
    for row in table.rows:
        print([cell.text for cell in row.cells])
    print('---')
