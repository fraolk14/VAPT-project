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


def _nmap_confirmed_ports(nmap_findings: list[dict[str, Any]]) -> set[int]:
    """Return the set of ports Nmap confirmed as open."""
    return {
        int(f.get("port") or 0)
        for f in nmap_findings
        if f.get("state") == "open" and f.get("port")
    }


def _boost_socket_finding(sock_f: dict[str, Any], nmap_port_meta: dict[str, Any]) -> dict[str, Any]:
    """
    Nmap confirmed the port is open but title-key didn't match.
    Boost confidence and tag as dual-confirmed with Nmap port-open evidence.
    """
    boosted = dict(sock_f)
    boosted["source"] = "nmap+socket"
    boosted["confidence"] = 0.95

    # Prepend Nmap port-open evidence
    nmap_evidence = nmap_port_meta.get("evidence", "")
    sock_evidence = (sock_f.get("evidence") or "").strip()
    if nmap_evidence and nmap_evidence not in sock_evidence:
        boosted["evidence"] = f"[NMAP] {nmap_evidence}\n\n[SOCKET] {sock_evidence}"

    # Union CVEs
    boosted["cve_id"] = _merge_cves(sock_f.get("cve_id"), nmap_port_meta.get("cve_id"))

    # Union compliance
    boosted["compliance_map"] = _merge_compliance(
        sock_f.get("compliance_map", []),
        nmap_port_meta.get("compliance_map", []),
    )

    meta = dict(sock_f.get("metadata") or {})
    meta["confirmed_by"] = sorted({"nmap", "socket"})
    meta["dual_engine_confirmed"] = True
    meta["nmap_port_confirmation"] = {
        "nmap_service": nmap_port_meta.get("metadata", {}).get("nmap_service"),
        "nmap_product": nmap_port_meta.get("metadata", {}).get("nmap_product"),
        "nmap_version": nmap_port_meta.get("metadata", {}).get("nmap_version"),
        "nmap_extrainfo": nmap_port_meta.get("metadata", {}).get("nmap_extrainfo"),
    }
    boosted["metadata"] = meta
    return boosted


def correlate_network_findings(
    nmap_findings: list[dict[str, Any]],
    socket_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge Nmap and Python socket scanner findings into one correlated list.

    Pass 1 — Exact (port, title-key) match:
        Both scanners found the same issue → merge into one enriched record,
        confidence=0.97, source="nmap+socket".

    Pass 2 — Same-port confirmation:
        Nmap confirmed a port is open → boost all socket findings on that
        port to confidence=0.95 and tag as dual-confirmed, even when the
        titles differ (e.g. Nmap says "Open port 3000/tcp – http" while
        the socket scanner says "Missing CSP header on port 3000").
    """
    # Build port → best nmap open-port finding index
    nmap_port_open: dict[int, dict[str, Any]] = {}
    for f in nmap_findings:
        port = int(f.get("port") or 0)
        if port and f.get("state") == "open":
            existing = nmap_port_open.get(port)
            if existing is None or float(f.get("cvss_score") or 0) >= float(existing.get("cvss_score") or 0):
                nmap_port_open[port] = f

    # Index socket findings by (port, title-key)
    socket_index: dict[tuple[int, str], dict[str, Any]] = {}
    for f in socket_findings:
        key = _port_key(f)
        if key not in socket_index or float(f.get("cvss_score") or 0) > float(socket_index[key].get("cvss_score") or 0):
            socket_index[key] = f

    correlated: list[dict[str, Any]] = []
    matched_socket_keys: set[tuple[int, str]] = set()
    # Track which nmap open-port findings were used in Pass 1 merges
    nmap_port_used_in_pass1: set[int] = set()

    # ── Pass 1: exact title-key match ────────────────────────────────────────
    for nmap_f in nmap_findings:
        key = _port_key(nmap_f)
        if key in socket_index:
            merged = _merge_pair(nmap_f, socket_index[key])
            correlated.append(merged)
            matched_socket_keys.add(key)
            nmap_port_used_in_pass1.add(int(nmap_f.get("port") or 0))
        else:
            # Will handle in pass 2 or emit as nmap-only below
            pass

    # ── Pass 2: same-port confirmation for unmatched socket findings ─────────
    for key, sock_f in socket_index.items():
        if key in matched_socket_keys:
            continue  # already merged in pass 1
        port = key[0]
        if port in nmap_port_open:
            # Nmap confirmed this port open → boost the socket finding
            boosted = _boost_socket_finding(sock_f, nmap_port_open[port])
            correlated.append(boosted)
            matched_socket_keys.add(key)
        # else: socket-only (handled below)

    # ── Emit nmap-only findings (no socket counterpart on that port) ─────────
    socket_ports_with_findings = {k[0] for k in socket_index}
    for nmap_f in nmap_findings:
        key = _port_key(nmap_f)
        port = int(nmap_f.get("port") or 0)
        if key not in {_port_key(c) for c in correlated}:
            # Only emit as nmap-only if the socket scanner had no findings
            # on this port at all (avoids duplicate of the port-open finding
            # when the socket already covered every finding on that port)
            if port not in socket_ports_with_findings:
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
