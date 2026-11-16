"""Threat intelligence built from real, verifiable sources.

Key-free sources:
  * CISA Known Exploited Vulnerabilities (KEV) catalog — vulnerabilities exploited in the wild.
  * FIRST EPSS — probability that a CVE is exploited in the next 30 days.
  * Shodan InternetDB — open ports, CVEs, hostnames and tags for an IP.
  * GreyNoise Community — whether an IP mass-scans the internet, and its classification.
  * SANS ISC / DShield — attack reports for an IP and its network owner.
Optional (only when the key is set in the environment): VirusTotal, AbuseIPDB, AlienVault OTX.

No result is ever invented: a source that is unreachable or not configured is reported as such.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import date, datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding

UA = {"User-Agent": "VAPT-Platform-ThreatIntel/1.0"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
RISKY_PORTS = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 2375: "Docker API",
               3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_lock = threading.Lock()
_kev: dict[str, Any] ={"at": 0.0, "by_cve": {}, "version": None, "released": None, "status": "not_loaded"}
_epss_cache: dict[str, tuple[float, dict]] = {}


# ---------------------------------------------------------------------------
# CISA KEV and EPSS
# ---------------------------------------------------------------------------

def kev_catalog() -> dict[str, Any]:
    """The KEV catalog. Re-checked every 30 minutes with a conditional request, so a new CISA
    release shows up the same day without re-downloading the whole file each time.
    Never falls back to sample data."""
    with _lock:
        if _kev["by_cve"] and time.time() - _kev["at"] < 30 * 60:
            return _kev
        try:
            headers = dict(UA)
            if _kev["by_cve"] and _kev.get("etag"):
                headers["If-None-Match"] = _kev["etag"]
            if _kev["by_cve"] and _kev.get("last_modified"):
                headers["If-Modified-Since"] = _kev["last_modified"]
            r = requests.get(KEV_URL, headers=headers, timeout=30)
            if r.status_code == 304:
                _kev["at"] = time.time()
                _kev["status"] = "connected"
                return _kev
            r.raise_for_status()
            _kev["etag"] = r.headers.get("ETag")
            _kev["last_modified"] = r.headers.get("Last-Modified")
            data = r.json()
            _kev["by_cve"] = {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if v.get("cveID")}
            _kev["version"] = data.get("catalogVersion")
            _kev["released"] = data.get("dateReleased")
            _kev["status"] = "connected"
            _kev["at"] = time.time()
        except Exception as exc:
            if not _kev["by_cve"]:
                _kev["status"] = f"unavailable: {str(exc)[:100]}"
        return _kev


def epss_scores(cves: list[str]) -> dict[str, dict]:
    """EPSS score and percentile per CVE (batched, cached 24 h)."""
    now = time.time()
    out: dict[str, dict] = {}
    missing = []
    for cve in dict.fromkeys(c.upper() for c in cves):
        hit = _epss_cache.get(cve)
        if hit and now - hit[0] < 86400:
            if hit[1]:
                out[cve] = hit[1]
        else:
            missing.append(cve)
    for start in range(0, len(missing), 80):
        chunk = missing[start:start + 80]
        try:
            r = requests.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(chunk)}, headers=UA, timeout=20)
            r.raise_for_status()
            found = set()
            for row in r.json().get("data", []):
                cve = str(row.get("cve", "")).upper()
                entry = {"epss": float(row.get("epss") or 0), "percentile": float(row.get("percentile") or 0), "date": row.get("date")}
                _epss_cache[cve] = (now, entry)
                out[cve] = entry
                found.add(cve)
            for cve in chunk:
                if cve not in found:
                    _epss_cache[cve] = (now, {})
        except Exception:
            break
    return out


# ---------------------------------------------------------------------------
# Exposure: CVEs in the environment, prioritised by real-world exploitation
# ---------------------------------------------------------------------------

def _finding_target(f: Finding) -> str:
    meta = f.finding_metadata or {}
    return str(getattr(f, "target", None) or meta.get("host") or meta.get("hostname") or meta.get("ip_address") or meta.get("url") or "unknown")


def exposure(db: Session) -> dict[str, Any]:
    kev = kev_catalog()
    open_findings = [f for f in db.query(Finding).all() if str(f.status or "open").lower() in {"open", "in_progress"}]
    by_cve: dict[str, dict[str, Any]] = {}
    for f in open_findings:
        confirmed = {c.upper() for c in CVE_RE.findall(str(f.cve_id or ""))}
        possible = {str(c).upper() for c in ((f.finding_metadata or {}).get("possible_cves") or []) if CVE_RE.fullmatch(str(c))} - confirmed
        for cve in confirmed | possible:
            e = by_cve.setdefault(cve, {"cve": cve, "targets": set(), "findings": 0, "cvss": 0.0, "titles": set(), "severity": "info", "confirmed": False})
            e["confirmed"] = e["confirmed"] or cve in confirmed
            e["targets"].add(_finding_target(f))
            e["findings"] += 1
            e["cvss"] = max(e["cvss"], float(f.cvss_score or 0))
            e["titles"].add(f.title or "")
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sev = str(f.severity or "info").lower()
            if rank.get(sev, 4) < rank.get(e["severity"], 4):
                e["severity"] = sev

    scores = epss_scores(list(by_cve))
    rows = []
    for cve, e in by_cve.items():
        k = kev["by_cve"].get(cve)
        s = scores.get(cve)
        rows.append({
            "cve": cve,
            "confirmed": e["confirmed"],
            "targets": sorted(e["targets"]),
            "findings": e["findings"],
            "cvss": round(e["cvss"], 1),
            "severity": e["severity"],
            "title": sorted(e["titles"])[0] if e["titles"] else "",
            "epss": s["epss"] if s else None,
            "epss_percentile": s["percentile"] if s else None,
            "kev": {
                "name": k.get("vulnerabilityName"),
                "vendor": k.get("vendorProject"),
                "product": k.get("product"),
                "date_added": k.get("dateAdded"),
                "due_date": k.get("dueDate"),
                "ransomware": str(k.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "action": k.get("requiredAction"),
                "description": k.get("shortDescription"),
            } if k else None,
        })
    rows.sort(key=lambda r: (not r["confirmed"], r["kev"] is None, -(r["epss"] or 0), -r["cvss"], r["cve"]))
    confirmed_rows = [r for r in rows if r["confirmed"]]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kev_status": kev["status"],
        "kev_version": kev["version"],
        "kev_size": len(kev["by_cve"]),
        "summary": {
            "open_findings": len(open_findings),
            "findings_with_cve": sum(1 for f in open_findings if CVE_RE.search(str(f.cve_id or ""))),
            # Headline numbers count confirmed CVEs only; service-based guesses are reported apart.
            "distinct_cves": len(confirmed_rows),
            "in_kev": sum(1 for r in confirmed_rows if r["kev"]),
            "ransomware": sum(1 for r in confirmed_rows if r["kev"] and r["kev"]["ransomware"]),
            "high_epss": sum(1 for r in confirmed_rows if (r["epss"] or 0) >= 0.1),
            "max_epss": max((r["epss"] or 0 for r in confirmed_rows), default=0),
            "possible_cves": len(rows) - len(confirmed_rows),
            "possible_in_kev": sum(1 for r in rows if not r["confirmed"] and r["kev"]),
        },
        "cves": rows,
    }


def kev_recent(db: Session, days: int = 30) -> dict[str, Any]:
    kev = kev_catalog()
    cutoff = (date.today() - timedelta(days=days)).isoformat()
    env_cves = set()
    for f in db.query(Finding.cve_id).filter(Finding.cve_id.isnot(None)).all():
        env_cves |= {c.upper() for c in CVE_RE.findall(str(f[0] or ""))}
    items = [
        {
            "cve": cve,
            "name": v.get("vulnerabilityName"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "description": v.get("shortDescription"),
            "in_environment": cve in env_cves,
        }
        for cve, v in kev["by_cve"].items()
        if (v.get("dateAdded") or "") >= cutoff
    ]
    items.sort(key=lambda i: (i["date_added"] or "", i["cve"]), reverse=True)
    return {"status": kev["status"], "version": kev["version"], "days": days, "items": items}


# ---------------------------------------------------------------------------
# Indicator lookup
# ---------------------------------------------------------------------------

def _get(url: str, **kw) -> requests.Response | None:
    try:
        r = requests.get(url, timeout=kw.pop("timeout", 8), headers={**UA, **kw.pop("headers", {})}, **kw)
        return r
    except Exception:
        return None


def _geo(ip: str) -> dict | None:
    r = _get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon,hosting,proxy")
    if r is not None and r.ok and r.json().get("status") == "success":
        d = r.json()
        return {"country": d.get("country"), "cc": d.get("countryCode"), "region": d.get("regionName"), "city": d.get("city"),
                "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"), "lat": d.get("lat"), "lon": d.get("lon"),
                "hosting": d.get("hosting"), "proxy": d.get("proxy")}
    # Fallback: ipwho.is (ip-api.com rate-limits to 45 lookups/minute and is shared with the threat map).
    r = _get(f"https://ipwho.is/{ip}")
    if r is not None and r.ok and r.json().get("success"):
        d = r.json()
        conn = d.get("connection") or {}
        return {"country": d.get("country"), "cc": d.get("country_code"), "region": d.get("region"), "city": d.get("city"),
                "isp": conn.get("isp"), "org": conn.get("org"), "asn": f"AS{conn.get('asn')} {conn.get('org') or ''}".strip() if conn.get("asn") else None,
                "lat": d.get("latitude"), "lon": d.get("longitude"), "hosting": None, "proxy": None}
    return None


def _internetdb(ip: str) -> dict | None:
    r = _get(f"https://internetdb.shodan.io/{ip}")
    if r is None:
        return None
    if r.status_code == 404:
        return {"ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": [], "not_seen": True}
    return r.json() if r.ok else None


def _greynoise(ip: str) -> dict | None:
    r = _get(f"https://api.greynoise.io/v3/community/{ip}")
    if r is None:
        return None
    if r.status_code == 404:
        return {"noise": False, "riot": False, "classification": "not observed", "name": None, "last_seen": None, "link": None}
    if r.ok:
        d = r.json()
        return {k: d.get(k) for k in ("noise", "riot", "classification", "name", "last_seen", "link")}
    return None


def _dshield(ip: str) -> dict | None:
    r = _get(f"https://isc.sans.edu/api/ip/{ip}?json")
    if r is None or not r.ok:
        return None
    d = (r.json() or {}).get("ip") or {}
    return {"reports": d.get("count"), "targets": d.get("attacks"), "first_seen": d.get("mindate"), "last_seen": d.get("maxdate"),
            "network": d.get("asname"), "asn": d.get("as"), "abuse_contact": d.get("asabusecontact")}


def _virustotal(kind: str, value: str) -> dict | None:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return None
    path = "ip_addresses" if kind == "ip" else "domains"
    r = _get(f"https://www.virustotal.com/api/v3/{path}/{value}", headers={"x-apikey": key})
    if r is None or not r.ok:
        return None
    a = (r.json().get("data") or {}).get("attributes") or {}
    stats = a.get("last_analysis_stats") or {}
    return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "harmless": stats.get("harmless", 0),
            "reputation": a.get("reputation"), "link": f"https://www.virustotal.com/gui/{'ip-address' if kind == 'ip' else 'domain'}/{value}"}


def _abuseipdb(ip: str) -> dict | None:
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        return None
    r = _get("https://api.abuseipdb.com/api/v2/check", headers={"Key": key, "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90})
    if r is None or not r.ok:
        return None
    d = r.json().get("data") or {}
    return {"score": d.get("abuseConfidenceScore"), "reports": d.get("totalReports"), "last_reported": d.get("lastReportedAt"), "usage": d.get("usageType")}


def _otx(kind: str, value: str) -> dict | None:
    key = os.getenv("OTX_API_KEY", "").strip()
    if not key:
        return None
    path = "IPv4" if kind == "ip" else "domain"
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/{path}/{value}/general", headers={"X-OTX-API-KEY": key})
    if r is None or not r.ok:
        return None
    pulses = (r.json().get("pulse_info") or {})
    return {"pulses": pulses.get("count", 0), "names": [p.get("name") for p in (pulses.get("pulses") or [])[:5]]}


# Key-free feeds, probed live (a public test value, never user data) and cached for 5 minutes.
_FEED_PROBES = [
    ("FIRST EPSS", "Exploit probability for CVEs", "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"),
    ("Shodan InternetDB", "Ports, CVEs and tags per IP", "https://internetdb.shodan.io/8.8.8.8"),
    ("GreyNoise Community", "Internet-scanner classification", "https://api.greynoise.io/v3/community/8.8.8.8"),
    ("SANS ISC / DShield", "Attack reports per IP", "https://isc.sans.edu/api/ip/8.8.8.8?json"),
    ("abuse.ch Feodo Tracker", "Botnet C2 blocklist (live attack map)", "https://feodotracker.abuse.ch/downloads/ipblocklist.json"),
]
_probe_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_PROBE_TTL = 300


def _probe_feed(name: str, detail: str, url: str) -> dict[str, Any]:
    hit = _probe_cache.get(name)
    if hit and time.time() - hit[0] < _PROBE_TTL:
        return hit[1]
    started = time.perf_counter()
    try:
        r = requests.get(url, timeout=5, headers={"User-Agent": "VAPT-platform/1.0"})
        ms = round((time.perf_counter() - started) * 1000)
        if r.status_code == 429:
            status, note = "rate_limited", "Reachable but rate-limited right now"
        elif r.status_code < 500:
            status, note = "connected", detail
        else:
            status, note = "unavailable", f"HTTP {r.status_code}"
    except requests.RequestException as exc:
        ms, status, note = None, "unavailable", f"Unreachable ({exc.__class__.__name__})"
    result = {"name": name, "status": status, "detail": note, "latency_ms": ms, "checked_at": datetime.now(timezone.utc).isoformat()}
    _probe_cache[name] = (time.time(), result)
    return result


def sources_status() -> list[dict[str, Any]]:
    kev = kev_catalog()
    keyed = lambda env: "configured" if os.getenv(env, "").strip() else "needs_key"  # noqa: E731
    with ThreadPoolExecutor(max_workers=len(_FEED_PROBES)) as pool:
        probed = list(pool.map(lambda p: _probe_feed(*p), _FEED_PROBES))
    return [
        {"name": "CISA KEV", "status": "connected" if kev["status"] == "connected" else "unavailable",
         "detail": f"{len(kev['by_cve'])} exploited CVEs · catalog {kev['version'] or '—'}"},
        *probed,
        {"name": "VirusTotal", "status": keyed("VIRUSTOTAL_API_KEY"), "detail": "Set VIRUSTOTAL_API_KEY to enable"},
        {"name": "AbuseIPDB", "status": keyed("ABUSEIPDB_API_KEY"), "detail": "Set ABUSEIPDB_API_KEY to enable"},
        {"name": "AlienVault OTX", "status": keyed("OTX_API_KEY"), "detail": "Set OTX_API_KEY to enable"},
        {"name": "abuse.ch ThreatFox / URLhaus", "status": keyed("ABUSECH_API_KEY"), "detail": "Set ABUSECH_API_KEY (free abuse.ch Auth-Key) to enable"},
    ]


def lookup(db: Session, query: str) -> dict[str, Any]:
    q = (query or "").strip().lower()
    q = re.sub(r"^[a-z]+://", "", q).split("/")[0].split(":")[0] if q.count(":") <= 1 else q
    kind = None
    try:
        ipaddress.ip_address(q)
        kind = "ip"
    except ValueError:
        if DOMAIN_RE.match(q):
            kind = "domain"
    if not kind:
        return {"query": query, "error": "Enter an IPv4/IPv6 address or a domain name."}

    resolved: list[str] = []
    reverse = None
    if kind == "domain":
        try:
            resolved = sorted({ai[4][0] for ai in socket.getaddrinfo(q, None) if ai[0] == socket.AF_INET})[:5]
        except OSError:
            resolved = []
    else:
        resolved = [q]
        try:
            reverse = socket.gethostbyaddr(q)[0]
        except OSError:
            reverse = None

    ip = resolved[0] if resolved else None
    is_public = bool(ip) and ipaddress.ip_address(ip).is_global

    tasks: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        if ip and is_public:
            tasks["geo"] = pool.submit(_geo, ip)
            tasks["internetdb"] = pool.submit(_internetdb, ip)
            tasks["greynoise"] = pool.submit(_greynoise, ip)
            tasks["dshield"] = pool.submit(_dshield, ip)
            tasks["abuseipdb"] = pool.submit(_abuseipdb, ip)
        tasks["virustotal"] = pool.submit(_virustotal, kind, q)
        tasks["otx"] = pool.submit(_otx, kind, q)
        wait(list(tasks.values()), timeout=15)
    results = {k: (f.result() if f.done() else None) for k, f in tasks.items()}

    # KEV / EPSS for CVEs Shodan reports on the host
    vulns = [v.upper() for v in ((results.get("internetdb") or {}).get("vulns") or [])][:60]
    kev = kev_catalog()["by_cve"]
    epss = epss_scores(vulns) if vulns else {}
    host_cves = sorted(
        [{"cve": v, "kev": v in kev, "ransomware": str(kev.get(v, {}).get("knownRansomwareCampaignUse", "")).lower() == "known",
          "epss": (epss.get(v) or {}).get("epss")} for v in vulns],
        key=lambda c: (not c["kev"], -(c["epss"] or 0)),
    )

    # Your environment
    needles = {q, *resolved}
    assets = db.query(Asset).all()
    related_assets = [
        {"id": str(a.id), "name": a.hostname or a.asset_name or a.ip_address, "ip": a.ip_address, "criticality": a.criticality}
        for a in assets
        if needles & {str(a.ip_address or "").lower(), str(a.hostname or "").lower(), str(a.asset_name or "").lower()}
        or any(n and n in str(a.url or "").lower() for n in needles)
    ]
    related_findings = []
    for f in db.query(Finding).all():
        target = _finding_target(f).lower()
        if any(n and n in target for n in needles) and str(f.status or "open").lower() != "false_positive":
            related_findings.append({"id": str(f.id), "title": f.title, "severity": str(f.severity or "info").lower(), "status": f.status, "cve": f.cve_id})
    related_findings.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4))

    # Verdict with explicit reasons
    reasons: list[tuple[str, str]] = []
    gn = results.get("greynoise") or {}
    ds = results.get("dshield") or {}
    idb = results.get("internetdb") or {}
    vt = results.get("virustotal") or {}
    ab = results.get("abuseipdb") or {}
    if gn.get("classification") == "malicious":
        reasons.append(("bad", "GreyNoise classifies this IP as malicious."))
    elif gn.get("noise"):
        reasons.append(("warn", "GreyNoise has seen this IP scanning the internet."))
    if gn.get("riot"):
        service = f" ({gn['name']})" if gn.get("name") else ""
        reasons.append(("good", f"GreyNoise lists it as a known benign service{service}."))
    if ds.get("reports"):
        reasons.append(("bad" if (ds.get("reports") or 0) > 100 else "warn", f"SANS ISC recorded {ds['reports']:,} attack reports against {ds.get('targets') or 0} sensors."))
    if vt.get("malicious"):
        reasons.append(("bad", f"{vt['malicious']} VirusTotal engines flag it as malicious."))
    if (ab.get("score") or 0) >= 50:
        reasons.append(("bad", f"AbuseIPDB confidence score {ab['score']}% ({ab.get('reports')} reports)."))
    kev_hits = [c for c in host_cves if c["kev"]]
    if kev_hits:
        reasons.append(("bad", f"Shodan reports {len(kev_hits)} actively exploited (CISA KEV) CVEs on this host."))
    elif host_cves:
        reasons.append(("warn", f"Shodan reports {len(host_cves)} known CVEs on this host."))
    risky = [f"{p} ({RISKY_PORTS[p]})" for p in (idb.get("ports") or []) if p in RISKY_PORTS]
    if risky:
        reasons.append(("warn", "Exposes high-risk services: " + ", ".join(risky) + "."))
    if ip and not is_public:
        reasons.append(("info", "Private/internal address — internet reputation sources don't apply."))
    if not ip:
        reasons.append(("info", "The domain did not resolve to an IPv4 address."))

    level = "unknown" if not ip or not is_public else "clean"
    if any(r[0] == "bad" for r in reasons):
        level = "malicious"
    elif any(r[0] == "warn" for r in reasons):
        level = "suspicious"
    verdict_text = {
        "malicious": "Malicious indicators found",
        "suspicious": "Suspicious — review recommended",
        "clean": "No known bad reputation",
        "unknown": "Not enough external data",
    }[level]

    return {
        "query": q,
        "kind": kind,
        "resolved": resolved,
        "reverse_dns": reverse,
        "public": is_public,
        "verdict": {"level": level, "text": verdict_text, "reasons": [{"tone": t, "text": x} for t, x in reasons]},
        "geo": results.get("geo"),
        "internetdb": results.get("internetdb"),
        "greynoise": results.get("greynoise"),
        "dshield": results.get("dshield"),
        "virustotal": results.get("virustotal"),
        "abuseipdb": results.get("abuseipdb"),
        "otx": results.get("otx"),
        "host_cves": host_cves,
        "environment": {"assets": related_assets[:20], "findings": related_findings[:30]},
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
