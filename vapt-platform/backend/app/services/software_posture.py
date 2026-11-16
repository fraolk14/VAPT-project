"""Software governance built from the endpoint agent's installed-software inventory.

Each reported program is grouped into a product (version and architecture stripped from the
name), checked against the approved list, and tagged with a policy category such as
"remote access" or "crypto / trading". The category is a policy label from the product name,
not a vulnerability verdict. Network services found by port scans are counted separately; they
are not installed software.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.agent import AgentDevice
from app.models.software import Software, SoftwareAsset, WhitelistSoftware

_VERSIONISH = re.compile(r"(?<![a-z])[a-z]{0,3}\d+(?:[.\-_+]\d+)+\S*|\b(?:\d{4}|x64|x86|64-bit|32-bit|amd64|arm64)\b", re.I)
_BRACKETS = re.compile(r"\((?:x64|x86|64-bit|32-bit|amd64|arm64|user|machine|64 bit|32 bit)\)", re.I)
_SPACES = re.compile(r"\s+")
_SERVICE_NAME = re.compile(r"\((?:port\s+\d+|\d+/(?:tcp|udp))\)\s*$", re.I)
SERVICE_CATEGORIES = {"network", "web", "database"}
SERVICE_SOURCES = ("nmap", "subnet", "socket", "banner")

_SYSTEM = re.compile(
    r"windows driver package|microsoft visual c\+\+|redistributable|\bruntime\b|security update|update for|hotfix|"
    r"\bkb\d{6,}\b|\.net (?:framework|runtime|desktop)|microsoft edge webview|windows sdk|vs_|directx|"
    r"microsoft update health|intel\(r\)|realtek|nvidia|amd software|lenovo (?:vantage|system|monitor)|dell (?:update|command)|hp (?:support|system)",
    re.I,
)

# (key, label, risk, why it matters, keywords)
POLICY_CLASSES: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    ("offensive", "Hacking / credential tools", "high",
     "Used to steal credentials or attack other systems; rarely legitimate on a user endpoint.",
     ("mimikatz", "metasploit", "cain", "hashcat", "john the ripper", "cobalt strike", "lazagne", "responder")),
    ("remote-access", "Remote access", "high",
     "Gives someone outside the company interactive control of the machine, bypassing VPN and MFA.",
     ("anydesk", "teamviewer", "rustdesk", "vnc", "splashtop", "logmein", "screenconnect", "remote utilities", "ammyy", "supremo")),
    ("p2p", "Peer-to-peer / torrent", "high",
     "Common malware delivery route and a copyright and data-leak risk.",
     ("torrent", "utorrent", "bittorrent", "qbittorrent", "frostwire", "emule", "limewire")),
    ("crypto", "Crypto / trading", "medium",
     "Wallets and exchange clients attract targeted malware and are usually outside business use.",
     ("binance", "exodus", "metamask", "electrum", "coinbase", "ledger live", "trust wallet", "bitcoin core")),
    ("cloud-storage", "Personal cloud storage", "medium",
     "Company data can be synced to personal accounts outside your control.",
     ("megasync", "dropbox", "google drive", "pcloud", "box drive", "icloud", "mediafire", "sync.com")),
    ("network-tools", "Network / admin tools", "medium",
     "Legitimate for IT staff, suspicious on ordinary user endpoints.",
     ("wireshark", "nmap", "zenmap", "putty", "winscp", "angry ip", "advanced ip scanner", "netcat", "burp", "fiddler", "sysinternals", "process hacker")),
    ("games", "Games / emulators", "low",
     "Kernel-level anti-cheat drivers and emulators widen the attack surface.",
     ("steam", "epic games", "denuvo", "bluestacks", "riot", "battle.net", "ea app", "origin", "ubisoft", "noxplayer", "ldplayer")),
    ("messaging", "Personal messaging", "low",
     "Unmanaged chat apps can move files and data outside approved channels.",
     ("telegram", "whatsapp", "discord", "signal", "viber", "wechat", "skype")),
]
POLICY_LABEL = {k: label for k, label, *_ in POLICY_CLASSES}
RISK_ORDER = {"high": 0, "medium": 1, "low": 2, None: 3}


def product_key(name: str) -> str:
    """Normalise a program name so different versions of one product group together."""
    s = _BRACKETS.sub(" ", str(name or "").lower())
    s = _VERSIONISH.sub(" ", s)
    s = re.sub(r"[()\[\],]", " ", s)
    s = re.sub(r"\b(release|version|build|edition)\b", " ", s)
    return _SPACES.sub(" ", s).strip(" -_.") or str(name or "").strip().lower()


def policy_class(name: str) -> tuple[str, str, str, str] | None:
    low = str(name or "").lower()
    for key, label, risk, why, words in POLICY_CLASSES:
        if any(w in low for w in words):
            return key, label, risk, why
    return None


def is_system_component(name: str) -> bool:
    return bool(_SYSTEM.search(str(name or "")))


def is_network_service(software: Software, links: list[SoftwareAsset]) -> bool:
    if str(software.category or "").lower() in SERVICE_CATEGORIES:
        return True
    if _SERVICE_NAME.search(software.name or ""):
        return True
    return bool(links) and all(str(link.source or "").lower().startswith(SERVICE_SOURCES) for link in links)


def approved_keys(db: Session) -> dict[str, WhitelistSoftware]:
    return {product_key(w.name): w for w in db.query(WhitelistSoftware).all()}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def build_software_posture(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    approved = approved_keys(db)
    links_by_sw: dict[int, list[SoftwareAsset]] = defaultdict(list)
    for link in db.query(SoftwareAsset).all():
        links_by_sw[link.software_id].append(link)

    products: dict[str, dict[str, Any]] = {}
    endpoints: dict[str, dict[str, Any]] = {}
    services = 0
    for sw in db.query(Software).all():
        links = links_by_sw.get(sw.id, [])
        if is_network_service(sw, links):
            services += 1
            continue
        key = product_key(sw.name)
        cls = policy_class(sw.name)
        system = is_system_component(sw.name)
        p = products.setdefault(key, {
            "key": key,
            "name": sw.name,
            "vendor": sw.vendor,
            "versions": set(),
            "endpoints": set(),
            "paths": set(),
            "approved": key in approved,
            "approved_reason": approved[key].reason if key in approved else None,
            "approved_name": approved[key].name if key in approved else None,
            "policy": cls[0] if cls else None,
            "policy_label": cls[1] if cls else None,
            "risk": cls[2] if cls else None,
            "why": cls[3] if cls else None,
            "system": system,
            "cves": set(),
            "first_seen": None,
            "last_reported": None,
        })
        # Prefer the shortest spelling as the display name ("Wireshark" over "Wireshark 4.4.1 x64").
        if len(sw.name) < len(p["name"]):
            p["name"] = sw.name
        p["vendor"] = p["vendor"] or sw.vendor
        if sw.version:
            p["versions"].add(str(sw.version))
        p["cves"] |= set(sw.cves or [])
        # Software.updated_at moves every time an agent re-reports the program (any endpoint).
        reported = _utc(sw.updated_at) or _utc(sw.discovered_at)
        if reported and (p["last_reported"] is None or reported > p["last_reported"]):
            p["last_reported"] = reported
        for link in links:
            endpoint = link.endpoint_name or link.hostname or link.ip_address
            if not endpoint:
                continue
            p["endpoints"].add(endpoint)
            if link.installed_path:
                p["paths"].add(link.installed_path)
            seen = _utc(link.discovered_at)
            if seen and (p["first_seen"] is None or seen < p["first_seen"]):
                p["first_seen"] = seen
            e = endpoints.setdefault(endpoint, {"endpoint": endpoint, "ip_address": link.ip_address, "products": set(),
                                                "unapproved": set(), "risky": defaultdict(set), "first_inventory": None})
            e["products"].add(key)
            if not p["approved"] and not system:
                e["unapproved"].add(key)
            if cls and not p["approved"]:
                e["risky"][cls[0]].add(key)
            if seen and (e["first_inventory"] is None or seen < e["first_inventory"]):
                e["first_inventory"] = seen

    agents = {}
    for ag in db.query(AgentDevice).all():
        for name in (ag.hostname, ag.device_id):
            if name:
                agents[str(name).lower()] = ag

    product_rows = []
    for p in products.values():
        product_rows.append({
            **p,
            "versions": sorted(p["versions"]),
            "endpoints": sorted(p["endpoints"]),
            "endpoint_count": len(p["endpoints"]),
            "paths": sorted(p["paths"])[:4],
            "cves": sorted(p["cves"]),
            "first_seen": p["first_seen"].isoformat() if p["first_seen"] else None,
            "last_reported": p["last_reported"].isoformat() if p["last_reported"] else None,
        })
    product_rows.sort(key=lambda r: (r["approved"], r["system"], RISK_ORDER[r["risk"]], -r["endpoint_count"], r["name"].lower()))

    endpoint_rows = []
    for e in endpoints.values():
        ag = agents.get(str(e["endpoint"]).lower())
        endpoint_rows.append({
            "endpoint": e["endpoint"],
            "ip_address": e["ip_address"],
            "products": len(e["products"]),
            "unapproved": len(e["unapproved"]),
            "risky": {POLICY_LABEL[k]: len(v) for k, v in e["risky"].items()},
            "risky_total": sum(len(v) for v in e["risky"].values()),
            "agent_status": ag.status if ag else None,
            "agent_last_seen": _utc(ag.last_seen).isoformat() if ag and ag.last_seen else None,
            "first_inventory": e["first_inventory"].isoformat() if e["first_inventory"] else None,
        })
    endpoint_rows.sort(key=lambda r: (-r["risky_total"], -r["unapproved"], r["endpoint"]))

    policy_keys = [k for k, *_ in POLICY_CLASSES]
    cols = [r["endpoint"] for r in endpoint_rows[:12]]
    values = [[len(endpoints[c]["risky"].get(k, ())) for c in cols] for k in policy_keys]
    non_system = [r for r in product_rows if not r["system"]]
    risky = [r for r in product_rows if r["policy"] and not r["approved"]]

    return {
        "generated_at": now.isoformat(),
        "kpis": {
            "products": len(non_system),
            "endpoints": len(endpoint_rows),
            "unapproved": sum(1 for r in non_system if not r["approved"]),
            "risky": len(risky),
            "high_risk": sum(1 for r in risky if r["risk"] == "high"),
            "approved": sum(1 for r in product_rows if r["approved"]),
            "system_components": len(product_rows) - len(non_system),
            "network_services_excluded": services,
            "baseline_coverage": round(sum(1 for r in non_system if r["approved"]) / len(non_system), 3) if non_system else None,
        },
        "policy_classes": [
            {"key": k, "label": label, "risk": risk, "why": why,
             "products": sum(1 for r in risky if r["policy"] == k),
             "endpoints": len({e for r in risky if r["policy"] == k for e in r["endpoints"]})}
            for k, label, risk, why, _ in POLICY_CLASSES
        ],
        "matrix": {"rows": [{"key": k, "label": POLICY_LABEL[k]} for k in policy_keys], "cols": cols, "values": values},
        "products": product_rows,
        "endpoints": endpoint_rows,
        "approved_list": [
            {"id": w.id, "name": w.name, "reason": w.reason, "created_at": _utc(w.created_at).isoformat() if w.created_at else None}
            for w in sorted(approved.values(), key=lambda w: w.name.lower())
        ],
    }
