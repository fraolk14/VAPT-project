import subprocess
import uuid
import re

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.risk import Risk
from app.services.cve_lookup import lookup_cve_for_service
from app.services.risk_engine import calculate_risk


# -------------------------
# Run Nmap
# -------------------------
def run_nmap(target: str) -> str:
    """
    Executes an Nmap scan and returns raw output
    """
    result = subprocess.run(
        ["nmap", "-sV", target],
        capture_output=True,
        text=True
    )
    return result.stdout


# -------------------------
# Parse Nmap Output
# -------------------------
def parse_nmap_output(output: str):
    """
    Extract open ports/services from Nmap output
    """
    findings = []

    for line in output.splitlines():
        # Example:
        # 5432/tcp open  postgresql
        match = re.match(
            r"(\d+)/(\w+)\s+open\s+([\w\-]+)",
            line
        )
        if match:
            port, protocol, service = match.groups()
            findings.append({
                "port": int(port),
                "protocol": protocol,
                "service": service
            })

    return findings


# -------------------------
# Main Processing Logic
# -------------------------
def process_nmap_scan(db: Session, target: str, scan_id=None):
    """
    Full Nmap processing pipeline:
    - Run scan
    - Parse output
    - Enrich with CVEs
    - Save findings
    - Calculate and save risk
    """

    # 1. Run Nmap
    output = run_nmap(target)

    # 🔎 TEMP DEBUG (you can remove later)
    print("=== RAW NMAP OUTPUT ===")
    print(output)
    print("=== END OUTPUT ===")

    # 2. Parse results
    parsed_findings = parse_nmap_output(output)

    # 3. Store findings
    for item in parsed_findings:

        # ---- CVE enrichment ----
        cve_id, cvss_score, severity = lookup_cve_for_service(
            item["service"]
        )

        # ---- Save finding ----
        finding = Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            port=item["port"],
            protocol=item["protocol"],
            service=item["service"],
            state="open",
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity
        )
        db.add(finding)
        db.flush()  # 🔴 REQUIRED so finding.id exists

        # =====================================================
        # STEP 17.3 — APPLY RISK AFTER FINDING CREATION
        # =====================================================
        if cvss_score:
            risk_score, risk_level = calculate_risk(cvss_score)

            risk = Risk(
                id=uuid.uuid4(),
                finding_id=finding.id,
                risk_score=risk_score,
                risk_level=risk_level,
                recommendation="Apply security patch immediately"
            )
            db.add(risk)
        # =====================================================

    # 4. Commit everything
    db.commit()
