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
import re
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


# ---------------------------------------------------------------------------
# Ransomware victims (ransomware.live) — the only public, near-real-time source that names the
# organisations being attacked. Each entry is a claim a ransomware group published on its leak site.
# ---------------------------------------------------------------------------

RANSOMWARE_LIVE = os.getenv("RANSOMWARE_LIVE_API", "https://api.ransomware.live/v2")
_victim_cache: dict[str, tuple[float, list[dict]]] = {}


def _victim(row: dict) -> dict:
    return {
        "victim": (row.get("victim") or "").strip(),
        "group": row.get("group") or "",
        "sector": row.get("activity") if row.get("activity") not in (None, "", "Not Found") else "",
        "cc": (row.get("country") or "").upper(),
        "website": row.get("domain") or "",
        "discovered": row.get("discovered") or "",
        "attack_date": row.get("attackdate") or "",
        "url": row.get("url") or "",
    }


def _fetch_victims(path: str, ttl: int, timeout: int) -> list[dict]:
    cached = _victim_cache.get(path)
    if cached and time.time() - cached[0] < ttl:
        return cached[1]
    try:
        r = requests.get(f"{RANSOMWARE_LIVE}/{path}", headers=USER_AGENT, timeout=timeout)
        r.raise_for_status()
        rows = [_victim(x) for x in r.json() if isinstance(x, dict) and x.get("victim")]
        _victim_cache[path] = (time.time(), rows)
        _status("ransomware_live", True, len(rows) if path == "recentvictims" else _feed_status.get("ransomware_live", {}).get("count", 0),
                "ransomware.live — organisations claimed by ransomware groups on their leak sites")
        return rows
    except Exception as exc:
        _status("ransomware_live", False, 0, str(exc)[:160])
        return cached[1] if cached else []


def recent_victims() -> list[dict]:
    """The latest ~100 published victims worldwide (about the last two days)."""
    return _fetch_victims("recentvictims", ttl=900, timeout=25)


def country_victims(cc: str, days: int = 30) -> list[dict]:
    """Victims in one country published in the last `days` days, newest first."""
    rows = _fetch_victims(f"countryvictims/{cc.upper()}", ttl=6 * 3600, timeout=60)
    cutoff = (_now() - timedelta(days=days)).isoformat()
    rows = [v for v in rows if (v["discovered"] or "") >= cutoff]
    return sorted(rows, key=lambda v: v["discovered"], reverse=True)


# ---------------------------------------------------------------------------
# What an attacking IP actually did (DShield per-IP log). The attack type is inferred from the
# ports it hit on the sensors; the log itself is real.
# ---------------------------------------------------------------------------

# DShield sensors log connection attempts (mostly TCP SYN), not logins or payloads, so each label
# says what service was targeted rather than claiming a brute-force or exploit succeeded.
ATTACK_TYPES: dict[int, str] = {
    22: "SSH login targeting", 2222: "SSH login targeting", 23: "Telnet login targeting (IoT botnets)",
    2323: "Telnet login targeting (IoT botnets)", 445: "SMB targeting", 139: "SMB / NetBIOS probing",
    3389: "RDP targeting", 5900: "VNC targeting", 80: "Web exploitation / scanning",
    443: "Web exploitation / scanning", 8080: "Web exploitation / scanning", 8000: "Web exploitation / scanning",
    8443: "Web exploitation / scanning", 8888: "Web exploitation / scanning", 8081: "Web exploitation / scanning",
    1433: "Database targeting (MSSQL)", 3306: "Database targeting (MySQL)", 5432: "Database targeting (PostgreSQL)",
    6379: "Database targeting (Redis)", 27017: "Database targeting (MongoDB)", 9200: "Elasticsearch probing",
    2375: "Exposed Docker API probing", 5555: "Android Debug Bridge (ADB) targeting", 5060: "SIP / VoIP fraud scanning",
    25: "SMTP abuse / relay probing", 53: "DNS probing", 123: "NTP probing", 21: "FTP login targeting",
    1723: "PPTP VPN probing", 11211: "Memcached probing", 161: "SNMP probing",
}

# Organisations that scan the whole internet for research and exposure monitoring. Their traffic is
# real but not hostile, so they are tagged and kept out of the attack-type counts.
RESEARCH_SCANNERS = re.compile(
    r"censys|shodan|shadowserver|modat|rapid7|binaryedge|onyphe|stretchoid|leakix|driftnet|internet[- ]measurement|"
    r"recyber|criminal ip|aim(?:e|-)?\s?security|palo alto|expanse|cortex|netscout|cyble|ipip\.net|alpha strike|"
    r"academic|university|ruhr-uni|tum\b|caida|merit network|bitsight|securitytrails|quadmetrics|intrinsec",
    re.I,
)


def is_research_scanner(network: str) -> bool:
    return bool(RESEARCH_SCANNERS.search(network or ""))


_activity_cache: dict[str, tuple[float, dict]] = {}


def source_activity(ip: str) -> dict:
    """Ports, attack types and last activity for one DShield source (cached for an hour)."""
    cached = _activity_cache.get(ip)
    if cached and time.time() - cached[0] < 3600:
        return cached[1]
    result: dict[str, Any] = {"ip": ip, "records": 0, "ports": [], "attack_types": [], "last_activity": None, "available": False}
    try:
        r = requests.get(f"https://isc.sans.edu/api/ipdetails/{ip}?json", headers=USER_AGENT, timeout=20)
        r.raise_for_status()
        rows = [x for x in r.json() if isinstance(x, dict) and x.get("targetport") is not None]
    except Exception:
        _activity_cache[ip] = (time.time(), result)
        return result
    ports: dict[int, int] = {}
    last = ""
    for row in rows:
        try:
            port = int(row["targetport"])
        except (TypeError, ValueError):
            continue
        ports[port] = ports.get(port, 0) + 1
        stamp = f"{row.get('date', '')}T{row.get('time', '')}"
        last = max(last, stamp)
    types: dict[str, int] = {}
    for port, n in ports.items():
        types[ATTACK_TYPES.get(port, "Port scanning")] = types.get(ATTACK_TYPES.get(port, "Port scanning"), 0) + n
    if len(ports) >= 20:
        # Many distinct ports from one IP is a sweep, whatever the individual ports are.
        types = {"Mass port scanning": sum(ports.values()), **{k: v for k, v in types.items() if k != "Port scanning"}}
    result.update({
        "available": True,
        "records": sum(ports.values()),
        "ports": [{"port": p, "service": PORT_NAMES.get(p, ""), "hits": n} for p, n in sorted(ports.items(), key=lambda x: -x[1])[:8]],
        "distinct_ports": len(ports),
        "attack_types": [{"type": t, "hits": n} for t, n in sorted(types.items(), key=lambda x: -x[1])],
        "last_activity": (last + "Z") if last else None,
    })
    _activity_cache[ip] = (time.time(), result)
    return result


def country_detail(cc: str, window: str = "7d") -> dict:
    """Everything real we can say about one country: attacks launched from it, and organisations
    in it that ransomware groups have claimed."""
    from concurrent.futures import ThreadPoolExecutor

    cc = cc.upper()
    live = get_live_map(window)
    here = [s for s in live["sources"] if (s.get("cc") or "").upper() == cc]
    attackers = [s for s in here if s["kind"] == "attacker"][:12]
    with ThreadPoolExecutor(max_workers=5) as pool:
        activity = dict(zip([s["ip"] for s in attackers], pool.map(source_activity, [s["ip"] for s in attackers])))

    attack_types: dict[str, dict] = {}
    top_sources = []
    research = 0
    for s in attackers:
        act = activity.get(s["ip"]) or {}
        benign = is_research_scanner(s.get("asn", ""))
        research += 1 if benign else 0
        for t in ([] if benign else act.get("attack_types", [])):
            row = attack_types.setdefault(t["type"], {"type": t["type"], "hits": 0, "sources": 0})
            row["hits"] += t["hits"]
            row["sources"] += 1
        top_sources.append({
            "ip": s["ip"], "city": s.get("city"), "network": s.get("asn"), "reports": s["reports"], "targets": s["targets"],
            "attack_types": [t["type"] for t in act.get("attack_types", [])[:3]],
            "ports": act.get("ports", [])[:5], "distinct_ports": act.get("distinct_ports", 0),
            "last_activity": act.get("last_activity") or s.get("last_seen"), "detail_available": act.get("available", False),
            "research_scanner": benign,
        })
    # Hostile sources first; research scanners after them.
    top_sources.sort(key=lambda x: x["research_scanner"])
    malware = {}
    for s in here:
        if s["kind"] in {"c2", "malware"}:
            m = malware.setdefault(s.get("malware") or "Unknown", {"family": s.get("malware") or "Unknown", "servers": 0, "ips": []})
            m["servers"] += 1
            if len(m["ips"]) < 5:
                m["ips"].append(s["ip"])

    # Newest first, widening the window only when there is nothing more recent, and saying which.
    victims, scope = [v for v in recent_victims() if v["cc"] == cc], "last 48 hours"
    if not victims:
        victims, scope = country_victims(cc, days=30), "last 30 days"
    if not victims:
        victims, scope = country_victims(cc, days=365), "last 12 months"
    name = next((s["country"] for s in here), "")

    return {
        "cc": cc,
        "country": name,
        "window": live["window"],
        "generated_at": _now().isoformat(),
        "outbound": {
            "sources": len(here),
            "attackers": sum(1 for s in here if s["kind"] == "attacker"),
            "reports": sum(s["reports"] for s in here),
            "attack_types": sorted(attack_types.values(), key=lambda t: -t["hits"]),
            "research_scanners": research,
            "examined": len(attackers),
            "top_sources": top_sources,
            "botnets": sorted(malware.values(), key=lambda m: -m["servers"]),
            "destination_note": (
                "Destinations are SANS DShield's volunteer sensors worldwide. No public real-time feed names "
                "the organisations that scans and exploit attempts like these hit."
            ),
            "type_note": ("Attack type is inferred from the ports each source hit on the sensors; the sensors log "
                          "connection attempts, not logins, so 'targeting' means the service was attacked, not breached. "
                          "Known research scanners (e.g. Censys, Shodan) are tagged and left out of the counts."),
        },
        "inbound": {
            "victims": victims[:30],
            "total": len(victims),
            "scope": scope,
            "source": "ransomware.live",
            "note": ("Organisations ransomware groups claim to have breached, as published on their leak sites. "
                     "Claims are real and current but not independently verified; the attack itself usually "
                     "happened days or weeks before the claim."),
        },
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

    victims_by_cc: dict[str, int] = {}
    for v in recent_victims():
        if v["cc"]:
            victims_by_cc[v["cc"]] = victims_by_cc.get(v["cc"], 0) + 1

    return {
        **{k: v for k, v in data.items() if k != "sources"},
        "feeds": dict(_feed_status),
        "victims_by_country": victims_by_cc,
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
