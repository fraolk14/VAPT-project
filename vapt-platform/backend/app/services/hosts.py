"""Per-host assessment coverage: which engines have checked each host, how recently, and what is open.

Built from the scans and findings tables plus the asset inventory. A host is any target a
completed or failed network/web scan was pointed at, or that findings are recorded against.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.analytics import _target_of, _utc

SEVERITIES = ["critical", "high", "medium", "low", "info"]
OPEN = {"open", "in_progress", "reopened", "new", "triaged"}
RESOLVED = {"resolved", "closed", "fixed", "remediated"}
ENGINE_OF_TOOL = {"openvas": "network", "nmap": "network", "zap": "web", "mobsf": "mobile", "endpoint-agent": "agent"}
STALE_DAYS = 30


def host_key(value: Any) -> str:
    """Normalise a scan target or finding host to a comparable host string."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    raw = raw.split("/")[0]
    if raw.count(":") == 1:
        raw = raw.split(":")[0]
    return raw


def _is_range(value: str) -> bool:
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
            return net.num_addresses > 1
        except ValueError:
            return False
    return False


def build_hosts(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    stale_before = now - timedelta(days=STALE_DAYS)
    assets = db.query(Asset).filter(Asset.is_active.is_(True)).all()
    asset_by_token: dict[str, Asset] = {}
    for a in assets:
        for token in (host_key(a.ip_address), host_key(a.hostname), host_key(a.url)):
            if token:
                asset_by_token.setdefault(token, a)
    asset_names = {str(a.id): (a.hostname or a.ip_address or "") for a in assets}

    hosts: dict[str, dict[str, Any]] = {}

    def host(key: str) -> dict[str, Any]:
        return hosts.setdefault(key, {
            "host": key, "targets": set(), "engines": {}, "scans": 0, "failed_scans": 0, "last_scan": None,
            "last_scan_id": None, "last_scan_started": None, "open": {s: 0 for s in SEVERITIES}, "resolved": 0,
            "false_positive": 0, "services": set(), "new_since_last_scan": 0, "top": [],
        })

    ranges = []
    scan_by_id: dict[str, Scan] = {}
    for s in db.query(Scan).all():
        scan_by_id[str(s.id)] = s
        status = str(s.status or "").lower()
        if status not in {"completed", "failed"}:
            continue
        target = str(s.target or "")
        if _is_range(target):
            ranges.append(target)
            continue
        key = host_key(target)
        if not key:
            continue
        h = host(key)
        h["targets"].add(target)
        h["scans"] += 1
        engine = ENGINE_OF_TOOL.get(str(s.tool or "").lower(), str(s.scan_type or s.tool or "other").lower())
        when = _utc(s.finished_at) or _utc(s.created_at)
        if status == "failed":
            h["failed_scans"] += 1
        else:
            e = h["engines"].setdefault(engine, {"last": None, "runs": 0, "last_target": target})
            e["runs"] += 1
            if when and (e["last"] is None or when > e["last"]):
                e["last"], e["last_target"] = when, target
            if when and (h["last_scan"] is None or when > h["last_scan"]):
                h["last_scan"], h["last_scan_id"] = when, str(s.id)
                h["last_scan_started"] = _utc(s.started_at) or _utc(s.created_at)

    for f in db.query(Finding).all():
        key = host_key(_target_of(f, asset_names, {k: v.target for k, v in scan_by_id.items()}))
        if not key or key == "unknown" or key not in hosts:
            continue
        h = hosts[key]
        status = str(f.status or "open").lower()
        sev = str(f.severity or "info").lower()
        sev = sev if sev in SEVERITIES else "info"
        if status in RESOLVED:
            h["resolved"] += 1
            continue
        if status == "false_positive":
            h["false_positive"] += 1
            continue
        if status not in OPEN:
            continue
        h["open"][sev] += 1
        if f.service and f.port and str(f.service).lower() not in {"host", "tcpwrapped", "unknown", "network", "web"}:
            h["services"].add(f"{f.port}/{f.service}")
        detected = _utc(f.detected_at)
        if sev != "info" and h["last_scan_started"] and detected and detected >= h["last_scan_started"] - timedelta(minutes=1):
            h["new_since_last_scan"] += 1
        h["top"].append((SEVERITIES.index(sev), -(f.cvss_score or 0), f.title, str(f.id), sev))

    rows = []
    for key, h in hosts.items():
        a = asset_by_token.get(key)
        open_total = sum(h["open"][s] for s in SEVERITIES if s != "info")
        last = h["last_scan"]
        top, seen_titles = [], set()
        for item in sorted(h["top"]):
            if item[2] not in seen_titles:
                seen_titles.add(item[2])
                top.append(item)
            if len(top) == 5:
                break
        rows.append({
            "host": key,
            "targets": sorted(h["targets"]),
            "asset": {"id": str(a.id), "name": a.asset_name, "os": a.os or a.os_type, "exposure": a.exposure,
                      "criticality": a.criticality, "owner": a.owner} if a else None,
            "engines": {k: {"last": v["last"].isoformat() if v["last"] else None, "runs": v["runs"], "last_target": v["last_target"]}
                        for k, v in h["engines"].items()},
            "scans": h["scans"],
            "failed_scans": h["failed_scans"],
            "last_scan": last.isoformat() if last else None,
            "days_since_scan": (now - last).days if last else None,
            "stale": not last or last < stale_before,
            "open": h["open"],
            "open_total": open_total,
            "resolved": h["resolved"],
            "false_positive": h["false_positive"],
            "new_since_last_scan": h["new_since_last_scan"],
            "services": sorted(h["services"], key=lambda s: int(s.split("/")[0]) if s.split("/")[0].isdigit() else 0)[:16],
            "top_findings": [{"title": t, "id": i, "severity": s} for _, _, t, i, s in top],
        })
    weight = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}
    rows.sort(key=lambda r: (-sum(r["open"][s] * weight[s] for s in SEVERITIES), r["host"]))

    scanned = [r for r in rows if r["last_scan"]]
    recent_failures = sum(
        1 for s in scan_by_id.values()
        if str(s.status or "").lower() == "failed" and (_utc(s.created_at) or now) >= now - timedelta(days=30)
    )
    top12 = rows[:12]
    return {
        "generated_at": now.isoformat(),
        "stale_days": STALE_DAYS,
        "kpis": {
            "hosts": len(rows),
            "stale": sum(1 for r in rows if r["stale"]),
            "with_urgent": sum(1 for r in rows if r["open"]["critical"] + r["open"]["high"]),
            "open_findings": sum(r["open_total"] for r in rows),
            "failed_scans_30d": recent_failures,
            "median_days_since_scan": sorted(r["days_since_scan"] for r in scanned)[len(scanned) // 2] if scanned else None,
        },
        "matrix": {
            "rows": [{"key": s, "label": s} for s in ["critical", "high", "medium", "low"]],
            "cols": [r["host"] for r in top12],
            "values": [[r["open"][s] for r in top12] for s in ["critical", "high", "medium", "low"]],
        },
        "ranges_scanned": sorted(set(ranges))[:20],
        "hosts": rows,
    }
