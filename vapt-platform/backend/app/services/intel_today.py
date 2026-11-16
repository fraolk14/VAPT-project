"""What changed today in public vulnerability intelligence.

Three live sources, all key-free:
  * CISA KEV entries added in the last few days (exploited in the wild);
  * Microsoft's latest monthly security release from the MSRC CVRF API, including zero-days
    (Exploited:Yes) and entries Microsoft revised today;
  * CVEs NVD published in the last 24 hours.
Each source is cached briefly and reports its own status, so one outage never blanks the panel.
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.services.intel import CVE_RE, kev_catalog

UA = {"User-Agent": "VAPT-Platform-ThreatIntel/1.0", "Accept": "application/json"}
MSRC_UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
MSRC_DOC = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEVERITY_RANK = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3}

_lock = threading.Lock()
_cache: dict[str, tuple[float, Any]] = {}


def _cached(key: str, ttl: int, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
    value = fn()
    if value.get("status") == "connected":
        with _lock:
            _cache[key] = (time.time(), value)
    elif hit:  # keep serving the last good copy, marked stale
        return {**hit[1], "status": "stale", "note": value.get("note")}
    return value


def _text(node: Any) -> str:
    return str((node or {}).get("Value") or "") if isinstance(node, dict) else str(node or "")


def _microsoft() -> dict[str, Any]:
    try:
        r = requests.get(MSRC_UPDATES, headers=UA, timeout=20)
        r.raise_for_status()
        releases = sorted(r.json().get("value", []), key=lambda x: x.get("InitialReleaseDate") or "")
        if not releases:
            return {"status": "unavailable", "note": "MSRC returned no releases."}
        latest = releases[-1]
        doc = requests.get(MSRC_DOC.format(id=latest["ID"]), headers=UA, timeout=60)
        doc.raise_for_status()
        vulns = doc.json().get("Vulnerability", [])
    except (requests.RequestException, ValueError, KeyError) as exc:
        return {"status": "unavailable", "note": f"Microsoft MSRC unreachable ({exc.__class__.__name__})."}

    today = datetime.now(timezone.utc).date().isoformat()
    rows = []
    for v in vulns:
        threats = v.get("Threats") or []
        severities = {_text(t.get("Description")) for t in threats if t.get("Type") == 3}
        impacts = {_text(t.get("Description")) for t in threats if t.get("Type") == 0}
        exploit_text = " ".join(_text(t.get("Description")) for t in threats if t.get("Type") == 1)
        scores = [s.get("BaseScore") for s in (v.get("CVSSScoreSets") or []) if isinstance(s.get("BaseScore"), (int, float))]
        revisions = sorted((rv.get("Date") or "")[:10] for rv in (v.get("RevisionHistory") or []))
        severity = min(severities, key=lambda s: SEVERITY_RANK.get(s, 9)) if severities else None
        notes = v.get("Notes") or []
        cna = next((_text(n) for n in notes if n.get("Type") == 8), "")        # who issued the CVE
        family = next((_text(n) for n in notes if n.get("Type") == 7), "")     # product family
        rows.append({
            "cna": cna or "Microsoft",
            "microsoft": (cna or "Microsoft").lower() == "microsoft",
            "family": family,
            "cve": v.get("CVE"),
            "title": _text(v.get("Title")),
            "severity": severity,
            "impact": sorted(i for i in impacts if i)[:2],
            "cvss": max(scores) if scores else None,
            "exploited": "Exploited:Yes" in exploit_text,
            "disclosed": "Publicly Disclosed:Yes" in exploit_text,
            "last_revised": revisions[-1] if revisions else None,
            "first_published": revisions[0] if revisions else None,
        })
    rank = lambda r: (not r["exploited"], not r["disclosed"], SEVERITY_RANK.get(r["severity"], 9), -(r["cvss"] or 0))  # noqa: E731
    rows.sort(key=rank)
    # Microsoft also republishes fixes for open-source and Chromium components it ships (Azure Linux, Edge).
    # Those are counted, but the lists below show Microsoft-issued vulnerabilities.
    third_party = Counter(r["cna"] for r in rows if not r["microsoft"])
    rows = [r for r in rows if r["microsoft"]]
    counts = Counter(r["severity"] or "Unrated" for r in rows)
    return {
        "status": "connected",
        "release": latest.get("ID"),
        "title": latest.get("DocumentTitle"),
        "released": latest.get("InitialReleaseDate"),
        "revised": latest.get("CurrentReleaseDate"),
        "total": len(rows),
        "counts": dict(counts),
        "third_party_total": sum(third_party.values()),
        "third_party_top": third_party.most_common(5),
        "exploited": [r for r in rows if r["exploited"]],
        "disclosed": [r for r in rows if r["disclosed"] and not r["exploited"]],
        "critical": [r for r in rows if r["severity"] == "Critical" and not r["exploited"]][:15],
        "revised_today": [r for r in rows if r["last_revised"] == today and r["first_published"] != today][:20],
        "published_today": [r for r in rows if r["first_published"] == today][:20],
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _nvd(hours: int = 24) -> dict[str, Any]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 500,
    }
    data = None
    for attempt in range(3):  # NVD often answers 503 under load
        try:
            r = requests.get(NVD_API, params=params, headers=UA, timeout=30)
            if r.status_code == 200:
                data = r.json()
                break
        except requests.RequestException:
            pass
        time.sleep(2 * (attempt + 1))
    if data is None:
        return {"status": "unavailable", "note": "NVD didn't answer (it is often overloaded). Try again in a few minutes."}

    items = []
    for wrapper in data.get("vulnerabilities", []):
        c = wrapper.get("cve") or {}
        if str(c.get("vulnStatus", "")).lower() == "rejected":
            continue
        metrics = c.get("metrics") or {}
        score, severity = None, None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key) or []:
                d = m.get("cvssData") or {}
                if isinstance(d.get("baseScore"), (int, float)) and (score is None or d["baseScore"] > score):
                    score, severity = d["baseScore"], (d.get("baseSeverity") or m.get("baseSeverity"))
            if score is not None:
                break
        desc = next((x.get("value") for x in c.get("descriptions") or [] if x.get("lang") == "en"), "")
        items.append({
            "cve": c.get("id"),
            "published": c.get("published"),
            "cvss": score,
            "severity": (severity or "").lower() or None,
            "source": c.get("sourceIdentifier"),
            "description": (desc or "")[:400],
        })
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda i: (sev_rank.get(i["severity"] or "", 9), -(i["cvss"] or 0), i["cve"] or ""))
    import re as _re

    def _publisher(source: str | None) -> str:
        name = (source or "unknown").split("@")[-1]
        return "unnamed CNA" if _re.fullmatch(r"[0-9a-f-]{36}", name) else name

    by_source = Counter(_publisher(i["source"]) for i in items)
    return {
        "status": "connected",
        "hours": hours,
        "total": data.get("totalResults", len(items)),
        "listed": len(items),
        "critical": sum(1 for i in items if i["severity"] == "critical"),
        "high": sum(1 for i in items if i["severity"] == "high"),
        "unscored": sum(1 for i in items if i["cvss"] is None),
        "top": items[:25],
        "by_source": by_source.most_common(8),
        "checked_at": end.isoformat(),
    }


def today_feed(db: Session, kev_days: int = 3) -> dict[str, Any]:
    env_cves: set[str] = set()
    for (cve_text,) in db.query(Finding.cve_id).filter(Finding.cve_id.isnot(None)).all():
        env_cves |= {c.upper() for c in CVE_RE.findall(str(cve_text or ""))}

    kev = kev_catalog()
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=kev_days - 1)).isoformat()
    kev_new = sorted(
        (
            {"cve": cve, "name": v.get("vulnerabilityName"), "vendor": v.get("vendorProject"), "product": v.get("product"),
             "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
             "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
             "action": v.get("requiredAction"), "in_environment": cve in env_cves}
            for cve, v in kev["by_cve"].items() if (v.get("dateAdded") or "") >= cutoff
        ),
        key=lambda i: (i["date_added"] or "", i["cve"]), reverse=True,
    )
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as pool:
        ms_job = pool.submit(_cached, "msrc", 3600, _microsoft)
        nvd_job = pool.submit(_cached, "nvd24", 1800, _nvd)
        ms, nvd = ms_job.result(), nvd_job.result()
    for group in ("exploited", "disclosed", "critical", "revised_today", "published_today"):
        for row in ms.get(group, []) if isinstance(ms, dict) else []:
            row["in_kev"] = (row.get("cve") or "").upper() in kev["by_cve"]
            row["in_environment"] = (row.get("cve") or "").upper() in env_cves
    for row in nvd.get("top", []) if isinstance(nvd, dict) else []:
        row["in_environment"] = (row.get("cve") or "").upper() in env_cves
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kev": {"status": kev["status"], "version": kev["version"], "released": kev.get("released"), "days": kev_days, "items": kev_new},
        "microsoft": ms,
        "nvd": nvd,
    }
