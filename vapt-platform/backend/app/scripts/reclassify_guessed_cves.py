"""Move CVEs that were guessed from a port or service name out of findings' cve_id.

Older releases tagged findings with CVEs based only on an open port or a service name (any SMB
port got EternalBlue, any nginx got CVE-2023-44487, ...). Those CVEs are moved to
finding_metadata["possible_cves"] so they no longer count as confirmed exposure, and a severity
the guess had raised to critical 9.8 is put back to the port-based rating. The previous values
are kept in finding_metadata["cve_reclassified"].

Usage (inside the api container):
    python -m app.scripts.reclassify_guessed_cves            # dry run: show what would change
    python -m app.scripts.reclassify_guessed_cves --apply    # write the changes
"""
import sys
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models.finding import Finding
from app.services.nmap_scanner import _service_severity
from app.services.scan_correlator import POSSIBLE_CVE_NOTE, split_guessed_cves


def _evidence_text(f: Finding) -> str:
    meta = f.finding_metadata or {}
    return " ".join(filter(None, [
        f.title or "", f.service or "", f.evidence or "",
        str(meta.get("nmap_product") or ""), str(meta.get("nmap_version") or ""),
        f"{f.port}/tcp",
    ]))


def _restored_severity(f: Finding) -> tuple[str, float] | None:
    """The old heuristic raised guessed findings to critical 9.8; undo only that bump."""
    if str(f.severity or "").lower() != "critical" or float(f.cvss_score or 0) != 9.8:
        return None
    if "actuator" in f"{f.title} {f.evidence}".lower():
        return "medium", 5.3  # exposed Spring actuator endpoint: information disclosure
    if f.port:
        return _service_severity(int(f.port), f.service or "", "open")
    return "medium", 5.3


def main() -> int:
    apply = "--apply" in sys.argv
    db = SessionLocal()
    changed = 0
    try:
        for f in db.query(Finding).filter(Finding.cve_id.isnot(None)).all():
            new_cve, moved = split_guessed_cves(f.cve_id, _evidence_text(f))
            if not moved:
                continue
            changed += 1
            restored = _restored_severity(f) if not new_cve or "CVE-" not in new_cve.upper() else None
            print(f"{f.id}  {f.cve_id!r} -> {new_cve!r}  possible={moved}"
                  + (f"  severity {f.severity}/{f.cvss_score} -> {restored[0]}/{restored[1]}" if restored else ""))
            if not apply:
                continue
            meta = dict(f.finding_metadata or {})
            meta["possible_cves"] = sorted(set(meta.get("possible_cves") or []) | set(moved))
            meta["possible_cve_note"] = POSSIBLE_CVE_NOTE
            meta["cve_reclassified"] = {
                "at": datetime.now(timezone.utc).isoformat(),
                "previous_cve_id": f.cve_id,
                "previous_severity": f.severity,
                "previous_cvss": f.cvss_score,
            }
            f.finding_metadata = meta
            f.cve_id = new_cve
            if restored:
                f.severity, f.cvss_score = restored
        if apply:
            db.commit()
        print(f"{changed} finding(s) {'updated' if apply else 'would change (dry run; pass --apply to write)'}.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
