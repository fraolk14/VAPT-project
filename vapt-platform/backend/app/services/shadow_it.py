"""Shadow IT built from real telemetry.

Three sources, all already in the database:
  * devices the scanners discovered and auto-registered (tag "scan-discovered") that nobody has
    reviewed or claimed yet;
  * hosts that appear in scan findings but have no inventory entry at all;
  * unsanctioned apps the endpoint agent reports (remote-access tools, personal cloud storage,
    removable media, browser extensions).
Nothing is scored or extrapolated beyond what those rows say.
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.services.analytics import _target_of, _utc

SEVERITIES = ["critical", "high", "medium", "low", "info"]
OPEN = {"open", "in_progress", "reopened", "new", "triaged"}
NETWORK_SOURCES = {"socket", "network-db", "nmap", "nmap+socket", "openvas"}
MANAGED_TAGS = {"managed-agent", "vap-agent-active"}
REVIEW_PREFIX = "reviewed:"
IGNORED_SERVICES = {"host", "unknown", "network-block", "tcpwrapped"}

APP_CATEGORIES = [
    ("remote-access", "Remote access tools", ("remote access", "anydesk", "teamviewer", "rustdesk", "vnc", "splashtop", "logmein", "screenconnect", "remote control")),
    ("cloud-storage", "Personal cloud storage", ("cloud storage", "megasync", "mega sync", "dropbox", "google drive", "pcloud", "box sync", "icloud")),
    ("removable-media", "Removable media", ("usb", "mass storage", "removable")),
    ("browser-extensions", "Browser extensions", ("extension",)),
    ("other", "Other unsanctioned software", ()),
]
CATEGORY_LABEL = {k: label for k, label, _ in APP_CATEGORIES}
KNOWN_APPS = {
    "anydesk": "AnyDesk", "teamviewer": "TeamViewer", "rustdesk": "RustDesk", "megasync": "MEGAsync",
    "dropbox": "Dropbox", "google drive": "Google Drive", "splashtop": "Splashtop", "screenconnect": "ScreenConnect",
}

_DETECTED = re.compile(r"detected:\s*(.+)$", re.I)
_ENDPOINT = re.compile(r"endpoint:\s*([^\n\r]+)", re.I)
_VERSION = re.compile(r"version:\s*([^)\n]+)\)?", re.I)
_COUNT = re.compile(r"\((\d+)\s+(?:installed|total)", re.I)


def _norm(value: Any) -> str:
    value = str(value or "").strip().lower()
    if "://" in value:
        value = urlparse(value).netloc or value
    return value.split("/")[0].split(":")[0]


def _tags(asset: Asset) -> list[str]:
    return [str(t) for t in (asset.tags or [])]


def review_state(asset: Asset) -> str | None:
    for tag in _tags(asset):
        if tag.startswith(REVIEW_PREFIX):
            return tag[len(REVIEW_PREFIX):]
    return None


def classify_app(title: str) -> tuple[str, str]:
    """Return (category key, app name) for an endpoint-agent shadow-IT finding title."""
    low = title.lower()
    category = next((key for key, _, words in APP_CATEGORIES if words and any(w in low for w in words)), "other")
    name = next((pretty for key, pretty in KNOWN_APPS.items() if key in low), None)
    if not name:
        if category == "removable-media":
            name = "USB mass storage"
        elif category == "browser-extensions":
            name = "Chrome extensions" if "chrome" in low else "Edge extensions" if "edge" in low else "Firefox add-ons" if "firefox" in low else "Browser extensions"
        else:
            m = _DETECTED.search(title)
            name = (m.group(1) if m else title).strip()[:80]
    return category, name


def build_shadow_posture(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    assets = db.query(Asset).filter(Asset.is_active.is_(True)).all()
    findings = db.query(Finding).all()
    asset_by_id = {str(a.id): a for a in assets}
    asset_names = {str(a.id): (a.hostname or a.ip_address or a.asset_name or "") for a in assets}

    known: set[str] = set()
    for a in assets:
        known |= {t for t in (_norm(a.ip_address), _norm(a.hostname), _norm(a.url)) if t}

    # per-asset finding stats (open findings only)
    stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"open": 0, **{s: 0 for s in SEVERITIES}, "last_seen": None})
    untracked: dict[str, dict[str, Any]] = {}
    for f in findings:
        if str(f.status or "open").lower() not in OPEN:
            continue
        sev = str(f.severity or "info").lower()
        sev = sev if sev in SEVERITIES else "info"
        seen = _utc(f.last_seen) or _utc(f.detected_at)
        if f.asset_id:
            st = stats[str(f.asset_id)]
            st["open"] += 1
            st[sev] += 1
            if seen and (st["last_seen"] is None or seen > st["last_seen"]):
                st["last_seen"] = seen
        if f.source in NETWORK_SOURCES:
            meta = f.finding_metadata or {}
            host = _norm(meta.get("host") or meta.get("ip_address"))
            if host and host not in known and not host.endswith(".0"):
                u = untracked.setdefault(host, {"address": host, "findings": 0, "services": set(), "severity": "info",
                                                "first_seen": None, "last_seen": None, "sources": set()})
                u["findings"] += 1
                if f.service and str(f.service).lower() not in IGNORED_SERVICES:
                    u["services"].add(str(f.service))
                u["sources"].add(f.source)
                if SEVERITIES.index(sev) < SEVERITIES.index(u["severity"]):
                    u["severity"] = sev
                d = _utc(f.detected_at)
                if d and (u["first_seen"] is None or d < u["first_seen"]):
                    u["first_seen"] = d
                if seen and (u["last_seen"] is None or seen > u["last_seen"]):
                    u["last_seen"] = seen

    # ---- devices ----
    devices, managed_endpoints = [], []
    counts = {"managed": 0, "unreviewed": 0, "sanctioned": 0, "unsanctioned": 0, "registered": 0}
    for a in assets:
        tags = _tags(a)
        state = review_state(a)
        if MANAGED_TAGS & set(tags):
            counts["managed"] += 1
            managed_endpoints.append(a)
            continue
        if state in ("sanctioned", "unsanctioned"):
            counts[state] += 1
        elif "scan-discovered" in tags and not (a.owner or "").strip():
            state = "unreviewed"
            counts["unreviewed"] += 1
        else:
            counts["registered"] += 1
            continue
        st = stats.get(str(a.id), {"open": 0, **{s: 0 for s in SEVERITIES}, "last_seen": None})
        services = sorted({t.split(":", 1)[1] for t in tags if t.startswith("service:")} - IGNORED_SERVICES)
        devices.append({
            "id": str(a.id),
            "name": a.asset_name or a.hostname or a.ip_address,
            "address": a.ip_address or a.hostname or a.url or "",
            "url": a.url,
            "type": a.asset_type,
            "exposure": str(a.exposure or "internal").lower(),
            "services": services,
            "owner": a.owner,
            "business_unit": a.business_unit,
            "state": state,
            "first_seen": a.created_at.isoformat() if a.created_at else None,
            "last_seen": st["last_seen"].isoformat() if st["last_seen"] else None,
            "open_findings": st["open"],
            **{s: st[s] for s in SEVERITIES},
        })
    devices.sort(key=lambda d: (d["state"] != "unreviewed", d["exposure"] != "external", -(d["critical"] * 10 + d["high"] * 5 + d["medium"] * 2), d["address"]))

    # ---- shadow apps from the endpoint agent ----
    apps: dict[str, dict[str, Any]] = {}
    per_endpoint: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        if "shadow" not in str(f.category or "").lower() or str(f.status or "open").lower() not in OPEN:
            continue
        title = str(f.title or "")
        category, name = classify_app(title)
        evidence = str(f.evidence or "")
        m = _ENDPOINT.search(evidence)
        endpoint = (m.group(1).strip() if m else None) or _target_of(f, asset_names, {})
        sev = str(f.severity or "info").lower()
        sev = sev if sev in SEVERITIES else "info"
        app = apps.setdefault(f"{category}:{name.lower()}", {
            "key": f"{category}:{name.lower()}", "name": name, "category": category, "category_label": CATEGORY_LABEL[category],
            "severity": sev, "endpoints": set(), "versions": set(), "findings": 0, "first_seen": None, "last_seen": None,
            "evidence": None, "remediation": None, "max_count": None,
        })
        app["findings"] += 1
        app["endpoints"].add(endpoint)
        if SEVERITIES.index(sev) < SEVERITIES.index(app["severity"]):
            app["severity"] = sev
        v = _VERSION.search(evidence)
        if v:
            app["versions"].add(v.group(1).strip())
        c = _COUNT.search(title)
        if c:
            app["max_count"] = max(app["max_count"] or 0, int(c.group(1)))
        if not app["evidence"] and evidence:
            app["evidence"] = evidence[:700]
        if not app["remediation"] and f.remediation:
            app["remediation"] = f.remediation
        d, seen = _utc(f.detected_at), _utc(f.last_seen) or _utc(f.detected_at)
        if d and (app["first_seen"] is None or d < app["first_seen"]):
            app["first_seen"] = d
        if seen and (app["last_seen"] is None or seen > app["last_seen"]):
            app["last_seen"] = seen
        per_endpoint[endpoint][category] += 1

    app_rows = sorted(
        ({**a, "endpoints": sorted(a["endpoints"]), "endpoint_count": len(a["endpoints"]), "versions": sorted(a["versions"]),
          "first_seen": a["first_seen"].isoformat() if a["first_seen"] else None,
          "last_seen": a["last_seen"].isoformat() if a["last_seen"] else None} for a in apps.values()),
        key=lambda r: (SEVERITIES.index(r["severity"]), -r["endpoint_count"], r["name"]),
    )
    endpoint_cols = sorted(per_endpoint, key=lambda e: -sum(per_endpoint[e].values()))[:12]
    categories = [k for k, _, _ in APP_CATEGORIES]

    untracked_rows = sorted(
        ({**u, "services": sorted(u["services"]), "sources": sorted(u["sources"]),
          "first_seen": u["first_seen"].isoformat() if u["first_seen"] else None,
          "last_seen": u["last_seen"].isoformat() if u["last_seen"] else None} for u in untracked.values()),
        key=lambda r: (SEVERITIES.index(r["severity"]), -r["findings"]),
    )
    unowned_external = [
        {"id": str(a.id), "name": a.asset_name or a.hostname or a.ip_address, "address": a.ip_address or a.url or a.hostname or ""}
        for a in assets if str(a.exposure or "").lower() == "external" and not (a.owner or "").strip()
    ]

    return {
        "generated_at": now.isoformat(),
        "kpis": {
            "unreviewed_devices": counts["unreviewed"],
            "untracked_hosts": len(untracked_rows),
            "shadow_apps": len(app_rows),
            "endpoints_with_apps": len(per_endpoint),
            "managed_endpoints": counts["managed"],
            "remote_access": sum(1 for a in app_rows if a["category"] == "remote-access"),
            "unowned_external": len(unowned_external),
            "sanctioned": counts["sanctioned"],
            "unsanctioned": counts["unsanctioned"],
        },
        "inventory": counts,
        "devices": devices,
        "untracked": untracked_rows,
        "apps": app_rows,
        "matrix": {
            "rows": [{"key": k, "label": CATEGORY_LABEL[k]} for k in categories],
            "cols": endpoint_cols,
            "values": [[per_endpoint[e].get(k, 0) for e in endpoint_cols] for k in categories],
        },
        "unowned_external": unowned_external,
    }
