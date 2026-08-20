"""
scan_correlator.py
──────────────────
Correlates findings from multiple network scanners (Nmap + Python socket
scanner, with extension points for OpenVAS) into a single, deduplicated,
enriched finding set.

Correlation rules:
  1. Same (port, normalised-title) → merge: keep higher CVSS, union CVEs,
     concat evidence from both sources.
  2. Nmap-only port findings with no Python confirmation → keep, mark
     "nmap-confirmed".
  3. Python socket findings with no Nmap counterpart → keep, mark
     "socket-confirmed".
  4. Findings confirmed by BOTH scanners get confidence boosted to 0.97
     and are tagged "dual-engine-confirmed".
"""

from __future__ import annotations

import re
from typing import Any

# ── normalise a title so minor wording differences don't prevent merging ───────
_TITLE_STRIP = re.compile(r"[^a-z0-9]+")


def _title_key(title: str) -> str:
    return _TITLE_STRIP.sub("", title.lower())[:60]


def _port_key(finding: dict[str, Any]) -> tuple[int, str]:
    """Primary merge key: (port, normalised_title_prefix)."""
    return (int(finding.get("port") or 0), _title_key(str(finding.get("title") or "")))


def _merge_cves(*cve_fields: str | None) -> str | None:
    """Union all CVE IDs from multiple fields."""
    seen: set[str] = set()
    for field in cve_fields:
        if field:
            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", field, re.IGNORECASE):
                seen.add(cve.upper())
    return ", ".join(sorted(seen)) if seen else None


def _merge_compliance(*maps: list[str]) -> list[str]:
    seen: set[str] = set()
    for m in maps:
        seen.update(m or [])
    return sorted(seen)


def _merge_pair(primary: dict[str, Any], secondary: dict[str, Any]) -> dict[str, Any]:
    """Merge secondary into primary, keeping the stronger data."""
    merged = dict(primary)

    # Higher CVSS wins
    p_cvss = float(primary.get("cvss_score") or 0)
    s_cvss = float(secondary.get("cvss_score") or 0)
    if s_cvss > p_cvss:
        merged["cvss_score"] = s_cvss
        merged["severity"] = secondary["severity"]

    # Union CVEs
    merged["cve_id"] = _merge_cves(primary.get("cve_id"), secondary.get("cve_id"))

    # Concat evidence from both sources
    p_src = primary.get("source", "scanner-a")
    s_src = secondary.get("source", "scanner-b")
    p_evidence = (primary.get("evidence") or "").strip()
    s_evidence = (secondary.get("evidence") or "").strip()
    if s_evidence and s_evidence != p_evidence:
        merged["evidence"] = f"[{p_src.upper()}] {p_evidence}\n\n[{s_src.upper()}] {s_evidence}"

    # Union compliance tags
    merged["compliance_map"] = _merge_compliance(
        primary.get("compliance_map", []),
        secondary.get("compliance_map", []),
    )

    # Boost confidence + tag as dual-confirmed
    merged["confidence"] = 0.97
    merged["source"] = "nmap+socket"

    # Merge metadata
    p_meta = dict(primary.get("metadata") or {})
    s_meta = dict(secondary.get("metadata") or {})
    merged_meta = {**s_meta, **p_meta}   # primary wins on key conflicts
    merged_meta["confirmed_by"] = sorted({p_src, s_src})
    merged_meta["dual_engine_confirmed"] = True
    merged["metadata"] = merged_meta

    return merged


def correlate_network_findings(
    nmap_findings: list[dict[str, Any]],
    socket_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge Nmap and Python socket scanner findings into one correlated list.

    Rules:
    - Findings at the same (port, title-key) are merged into a single
      enriched record tagged "dual-engine-confirmed".
    - Unmatched findings from either engine are kept and tagged with their
      source engine.
    - The output is sorted by CVSS score descending, then port ascending.
    """
    # Index socket findings by key
    socket_index: dict[tuple[int, str], dict[str, Any]] = {}
    for f in socket_findings:
        key = _port_key(f)
        # keep the highest-CVSS socket finding per key
        if key not in socket_index or float(f.get("cvss_score") or 0) > float(socket_index[key].get("cvss_score") or 0):
            socket_index[key] = f

    correlated: list[dict[str, Any]] = []
    matched_socket_keys: set[tuple[int, str]] = set()

    for nmap_f in nmap_findings:
        key = _port_key(nmap_f)
        if key in socket_index:
            # Both scanners confirmed this finding → merge
            merged = _merge_pair(nmap_f, socket_index[key])
            correlated.append(merged)
            matched_socket_keys.add(key)
        else:
            # Nmap only
            tagged = dict(nmap_f)
            tagged["source"] = "nmap"
            meta = dict(tagged.get("metadata") or {})
            meta["confirmed_by"] = ["nmap"]
            meta["dual_engine_confirmed"] = False
            tagged["metadata"] = meta
            correlated.append(tagged)

    # Add socket-only findings (not matched by Nmap)
    for key, sock_f in socket_index.items():
        if key in matched_socket_keys:
            continue
        tagged = dict(sock_f)
        tagged["source"] = "socket"
        meta = dict(tagged.get("metadata") or {})
        meta["confirmed_by"] = ["socket"]
        meta["dual_engine_confirmed"] = False
        tagged["metadata"] = meta
        correlated.append(tagged)

    # Sort: critical/high first, then by port
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _sort_key(f: dict[str, Any]) -> tuple[int, float, int]:
        sev = severity_order.get((f.get("severity") or "info").lower(), 4)
        cvss = -float(f.get("cvss_score") or 0)
        port = int(f.get("port") or 0)
        return (sev, cvss, port)

    correlated.sort(key=_sort_key)

    return correlated


def build_correlation_summary(
    correlated: list[dict[str, Any]],
    nmap_count: int,
    socket_count: int,
) -> dict[str, Any]:
    """Build a scan metadata summary for storage in engine_metadata."""
    dual = sum(1 for f in correlated if (f.get("metadata") or {}).get("dual_engine_confirmed"))
    nmap_only = sum(1 for f in correlated if f.get("source") == "nmap")
    socket_only = sum(1 for f in correlated if f.get("source") == "socket")

    by_severity: dict[str, int] = {}
    for f in correlated:
        sev = (f.get("severity") or "info").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "engines": ["nmap", "socket"],
        "nmap_raw_findings": nmap_count,
        "socket_raw_findings": socket_count,
        "correlated_total": len(correlated),
        "dual_engine_confirmed": dual,
        "nmap_only": nmap_only,
        "socket_only": socket_only,
        "severity_breakdown": by_severity,
        "correlation_method": "port+title-key deduplication with evidence merging",
    }
