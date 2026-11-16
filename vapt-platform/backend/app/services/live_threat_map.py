"""Live global threat map built only from real, public threat telemetry.

Sources (no API key needed unless noted):
  * SANS Internet Storm Center / DShield — IPs observed attacking its worldwide sensor network,
    with report and target counts, plus the most-targeted ports and the global INFOCON level.
  * abuse.ch Feodo Tracker — botnet command-and-control servers.
  * abuse.ch ThreatFox — recent malware IOCs (only when ABUSECH_API_KEY is set; abuse.ch now
    requires a free Auth-Key).
IP addresses are geolocated with ip-api.com (batch) and cached.

Nothing here is simulated: if a feed is unreachable, the map shows fewer points and the feed
status says why.
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

USER_AGENT = {"User-Agent": "VAPT-Platform-ThreatMap/1.0"}
CACHE_SECONDS = int(os.getenv("THREATMAP_CACHE_SECONDS", "600"))
GEO_TTL_SECONDS = 24 * 3600
DSHIELD_LIMIT = int(os.getenv("THREATMAP_DSHIELD_LIMIT", "200"))

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    1723: "PPTP", 2222: "SSH (alt)", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5060: "SIP",
    5432: "PostgreSQL", 5555: "ADB", 5900: "VNC", 6379: "Redis", 8000: "HTTP (alt)", 8080: "HTTP proxy",
    8443: "HTTPS (alt)", 8888: "HTTP (alt)", 9200: "Elasticsearch", 27017: "MongoDB",
}

_lock = threading.Lock()
_cache: dict[str, Any] = {"at": 0.0, "data": None}
_geo_cache: dict[str, tuple[float, dict | None]] = {}
_feed_status: dict[str, dict[str, Any]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _status(name: str, ok: bool, count: int = 0, detail: str = "") -> None:
    _feed_status[name] = {"status": "connected" if ok else "unavailable", "count": count, "detail": detail, "checked_at": _now().isoformat()}


def _public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Geolocation
# ---------------------------------------------------------------------------

def geolocate(ips: list[str]) -> dict[str, dict]:
    """Batch-geolocate IPs (ip-api.com allows 100 per request, 15 requests per minute)."""
    now = time.time()
    result: dict[str, dict] = {}
    missing: list[str] = []
    for ip in dict.fromkeys(ips):
        cached = _geo_cache.get(ip)
        if cached and now - cached[0] < GEO_TTL_SECONDS:
            if cached[1]:
                result[ip] = cached[1]
        elif _public(ip):
            missing.append(ip)
    for start in range(0, min(len(missing), 400), 100):
        chunk = missing[start:start + 100]
        try:
            response = requests.post(
                "http://ip-api.com/batch?fields=status,query,country,countryCode,city,lat,lon,as,org",
                json=chunk, headers=USER_AGENT, timeout=20,
            )
            response.raise_for_status()
            for row in response.json():
                ip = row.get("query")
                geo = None
                if row.get("status") == "success" and row.get("lat") is not None:
                    geo = {
                        "country": row.get("country") or "Unknown",
                        "cc": row.get("countryCode") or "",
                        "city": row.get("city") or "",
                        "lat": row.get("lat"),
                        "lon": row.get("lon"),
                        "asn": row.get("as") or row.get("org") or "",
                    }
                _geo_cache[ip] = (now, geo)
                if geo:
                    result[ip] = geo
        except Exception:
            break  # rate-limited or offline: use what we have
    return result


def home_location() -> dict:
    """Where this platform sits, for drawing arcs. Override with THREATMAP_HOME_IP."""
    ip = os.getenv("THREATMAP_HOME_IP", "").strip()
    if not ip:
        cached = _cache.get("home")
        if cached and time.time() - cached[0] < GEO_TTL_SECONDS:
            return cached[1]
        try:
            ip = requests.get("https://api.ipify.org?format=json", timeout=8).json().get("ip", "")
        except Exception:
            ip = ""
    geo = geolocate([ip]).get(ip) if ip else None
    home = {"label": "Your network", "country": geo["country"], "cc": geo["cc"], "city": geo["city"], "lat": geo["lat"], "lon": geo["lon"]} if geo else None
    _cache["home"] = (time.time(), home)
    return home


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------

def _dshield_sources() -> list[dict]:
    try:
        r = requests.get(f"https://isc.sans.edu/api/sources/attacks/{DSHIELD_LIMIT}?json", headers=USER_AGENT, timeout=20)
        r.raise_for_status()
        rows = [x for x in r.json() if isinstance(x, dict) and x.get("ip")]
        _status("dshield", True, len(rows), "SANS ISC sensor network — sources attacking the most targets")
        return rows
    except Exception as exc:
        _status("dshield", False, 0, str(exc)[:160])
        return []


def _dshield_ports() -> list[dict]:
    try:
        r = requests.get("https://isc.sans.edu/api/topports/records/12?json", headers=USER_AGENT, timeout=20)
        r.raise_for_status()
        data = r.json()
        rows = list(data.values()) if isinstance(data, dict) else data
        out = []
        for row in rows:
            if not isinstance(row, dict) or "targetport" not in row:
                continue
            port = int(row["targetport"])
            out.append({
                "port": port,
                "service": PORT_NAMES.get(port, ""),
                "records": int(row.get("records") or 0),
                "targets": int(row.get("targets") or 0),
                "sources": int(row.get("sources") or 0),
            })
        return out
    except Exception:
        return []


def _infocon() -> str:
    try:
        r = requests.get("https://isc.sans.edu/api/infocon?json", headers=USER_AGENT, timeout=10)
        return str(r.json().get("status") or "unknown").lower()
    except Exception:
        return "unknown"


def _feodo() -> list[dict]:
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=USER_AGENT, timeout=20)
        r.raise_for_status()
        rows = [x for x in r.json() if isinstance(x, dict) and x.get("ip_address")]
        _status("feodo", True, len(rows), "abuse.ch Feodo Tracker — botnet command & control servers")
        return rows
    except Exception as exc:
        _status("feodo", False, 0, str(exc)[:160])
        return []


def _threatfox() -> list[dict]:
    key = os.getenv("ABUSECH_API_KEY", "").strip()
    if not key:
        _feed_status["threatfox"] = {"status": "needs_key", "count": 0, "detail": "Set ABUSECH_API_KEY (free at auth.abuse.ch) to add ThreatFox malware IOCs.", "checked_at": _now().isoformat()}
        return []
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "get_iocs", "days": 1}, headers={**USER_AGENT, "Auth-Key": key}, timeout=20)
        r.raise_for_status()
        payload = r.json()
        rows = [x for x in (payload.get("data") or []) if isinstance(x, dict) and x.get("ioc_type") == "ip:port"]
        _status("threatfox", payload.get("query_status") == "ok", len(rows), "abuse.ch ThreatFox — malware IOCs (last 24 h)")
        return rows[:150]
    except Exception as exc:
        _status("threatfox", False, 0, str(exc)[:160])
        return []


# ---------------------------------------------------------------------------
# Map model
# ---------------------------------------------------------------------------

def _build() -> dict:
    dshield = _dshield_sources()
    feodo = _feodo()
    threatfox = _threatfox()

    ips = [r["ip"] for r in dshield] + [r["ip_address"] for r in feodo] + [str(r.get("ioc", "")).split(":")[0] for r in threatfox]
    geo = geolocate(ips)

    sources: list[dict] = []
    for r in dshield:
        g = geo.get(r["ip"])
        if not g:
            continue
        sources.append({
            "id": f"ds-{r['ip']}", "ip": r["ip"], "kind": "attacker", "feed": "DShield",
            "label": "Attacking source", "reports": int(r.get("count") or 0), "targets": int(r.get("attacks") or 0),
            "first_seen": r.get("firstseen"), "last_seen": r.get("lastseen"), **g,
        })
    for r in feodo:
        g = geo.get(r["ip_address"])
        if not g:
            continue
        sources.append({
            "id": f"fd-{r['ip_address']}", "ip": r["ip_address"], "kind": "c2", "feed": "Feodo Tracker",
            "label": f"{r.get('malware') or 'Botnet'} C2", "malware": r.get("malware"), "port": r.get("port"),
            "status": r.get("status"), "reports": 0, "targets": 0,
            "first_seen": (r.get("first_seen") or "")[:10], "last_seen": (r.get("last_online") or "")[:10], **g,
        })
    for r in threatfox:
        ip = str(r.get("ioc", "")).split(":")[0]
        g = geo.get(ip)
        if not g:
            continue
        sources.append({
            "id": f"tf-{r.get('id') or ip}", "ip": ip, "kind": "malware", "feed": "ThreatFox",
            "label": f"{r.get('malware_printable') or 'Malware'} ({r.get('threat_type_desc') or r.get('threat_type') or 'IOC'})",
            "malware": r.get("malware_printable"), "reports": 0, "targets": 0,
            "first_seen": (r.get("first_seen") or "")[:10], "last_seen": (r.get("last_seen") or r.get("first_seen") or "")[:10], **g,
        })

    return {
        "generated_at": _now().isoformat(),
        "home": home_location(),
        "sources": sources,
        "top_ports": _dshield_ports(),
        "infocon": _infocon(),
        "feeds": dict(_feed_status),
    }


def get_live_map(window: str = "7d") -> dict:
    """Cached live map, filtered to sources last seen inside the window (24h / 7d / 30d)."""
    with _lock:
        if not _cache["data"] or time.time() - _cache["at"] > CACHE_SECONDS:
            _cache["data"] = _build()
            _cache["at"] = time.time()
        data = _cache["data"]

    days = {"24h": 1, "7d": 7, "30d": 30}.get(window, 7)
    cutoff = (_now() - timedelta(days=days)).date().isoformat()
    sources = [s for s in data["sources"] if not s.get("last_seen") or s["last_seen"] >= cutoff]

    by_country: dict[str, dict] = {}
    by_asn: dict[str, dict] = {}
    for s in sources:
        c = by_country.setdefault(s["country"], {"country": s["country"], "cc": s["cc"], "sources": 0, "reports": 0, "c2": 0, "lat": s["lat"], "lon": s["lon"]})
        c["sources"] += 1
        c["reports"] += s["reports"]
        c["c2"] += 1 if s["kind"] in {"c2", "malware"} else 0
        if s.get("asn"):
            a = by_asn.setdefault(s["asn"], {"asn": s["asn"], "country": s["country"], "sources": 0, "reports": 0})
            a["sources"] += 1
            a["reports"] += s["reports"]

    return {
        **{k: v for k, v in data.items() if k != "sources"},
        "window": window if window in {"24h", "7d", "30d"} else "7d",
        "sources": sorted(sources, key=lambda s: (-s["reports"], s["ip"])),
        "countries": sorted(by_country.values(), key=lambda c: (-c["reports"], -c["sources"])),
        "networks": sorted(by_asn.values(), key=lambda a: (-a["reports"], -a["sources"]))[:12],
        "summary": {
            "sources": len(sources),
            "attackers": sum(1 for s in sources if s["kind"] == "attacker"),
            "c2": sum(1 for s in sources if s["kind"] in {"c2", "malware"}),
            "countries": len(by_country),
            "reports": sum(s["reports"] for s in sources),
            "cache_age_seconds": int(time.time() - _cache["at"]),
        },
        "note": (
            "Points are real IP addresses reported by public threat feeds, placed at their geolocation. "
            "Arcs point from each source to your network's location to show where internet-wide attack "
            "traffic originates; they are not connections observed on your network."
        ),
    }
