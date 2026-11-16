"""Security analytics: trends and remediation performance computed from stored findings and scans.

Everything here is derived from real rows — detected_at / resolved_at / status on findings,
started_at / finished_at / status on scans, and the asset inventory. Nothing is estimated or
extrapolated; where there is no data (e.g. nothing resolved yet) the value is None and the UI
says so.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RISK_SEVERITIES = ["critical", "high", "medium", "low"]

# Default remediation SLA (days from detection) used when a finding has no explicit sla_due_at.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SEVERITY_WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}

OPEN_STATUSES = {"open", "in_progress", "reopened", "new", "triaged"}
FP_STATUSES = {"false_positive", "false-positive"}
RESOLVED_STATUSES = {"resolved", "closed", "fixed", "remediated"}
ACCEPTED_STATUSES = {"accepted", "accepted_risk", "risk_accepted"}

AGE_BUCKETS = [(0, 7, "0–7 d"), (8, 30, "8–30 d"), (31, 90, "31–90 d"), (91, 180, "91–180 d"), (181, None, "180+ d")]
ENGINE_LABELS = {
    "zap": "Web (OWASP ZAP)",
    "openvas": "Network",
    "nmap": "Network (Nmap)",
    "nmap+socket": "Network (Nmap + probes)",
    "socket": "Network probes",
    "network-db": "Network service checks",
    "endpoint-agent": "Endpoint agent",
    "mobsf": "Mobile (MobSF)",
    "web": "Web checks",
    "nuclei": "Web (Nuclei)",
    "testssl": "TLS (testssl.sh)",
}

_TITLE_NOISE = re.compile(r"\s+(on|at|for)\s+(port\s+)?\d+.*$", re.I)


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _sev(value: Any) -> str:
    sev = str(value or "info").lower()
    return sev if sev in SEVERITIES else "info"


def _status(value: Any) -> str:
    return str(value or "open").lower()


def _target_of(f: Finding, asset_names: dict[str, str] | None = None, scan_targets: dict[str, str] | None = None) -> str:
    meta = f.finding_metadata or {}
    raw = meta.get("host") or meta.get("hostname") or meta.get("ip_address") or meta.get("url") or meta.get("target") or ""
    if not raw and asset_names and f.asset_id:
        raw = asset_names.get(str(f.asset_id), "")
    if not raw and scan_targets and f.scan_id:
        raw = scan_targets.get(str(f.scan_id), "")
    raw = str(raw)
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    return raw or "unknown"


def _issue_name(f: Finding) -> str:
    title = (f.title or "Untitled").strip()
    return _TITLE_NOISE.sub("", title)[:120] or title[:120]


def _host_tokens(asset: Asset) -> set[str]:
    tokens = set()
    for value in (asset.ip_address, asset.hostname, asset.url):
        value = str(value or "").strip().lower()
        if not value:
            continue
        if "://" in value:
            value = urlparse(value).netloc or value
        tokens.add(value.split(":")[0])
    return {t for t in tokens if t}


def _buckets(start: datetime, end: datetime, step: timedelta) -> list[tuple[datetime, datetime]]:
    out = []
    cursor = start
    while cursor < end:
        out.append((cursor, min(cursor + step, end)))
        cursor += step
    return out


def build_analytics(db: Session, days: int = 90, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    days = max(7, min(int(days or 90), 730))
    start = now - timedelta(days=days)
    step = timedelta(days=1) if days <= 31 else timedelta(days=7)
    # Align buckets so the last one ends now.
    n_buckets = int((now - start) / step) + (1 if (now - start) % step else 0)
    first = now - step * n_buckets
    spans = _buckets(first, now, step)

    findings = db.query(Finding).all()
    scans = db.query(Scan).all()
    assets = db.query(Asset).filter(Asset.is_active.is_(True)).all()

    asset_names = {str(a.id): (a.hostname or a.ip_address or a.asset_name or "") for a in assets}
    scan_targets = {str(s.id): str(s.target or "") for s in scans}
    target_of = lambda f: _target_of(f, asset_names, scan_targets)  # noqa: E731

    real = [f for f in findings if _status(f.status) not in FP_STATUSES]
    open_items = [f for f in real if _status(f.status) in OPEN_STATUSES]
    resolved = [f for f in real if _status(f.status) in RESOLVED_STATUSES]

    # ---- detection trend (new findings per bucket, by severity) ----
    detection = {sev: [0] * len(spans) for sev in SEVERITIES}
    for f in real:
        d = _utc(f.detected_at)
        if not d or d < first:
            continue
        idx = min(int((d - first) / step), len(spans) - 1)
        detection[_sev(f.severity)][idx] += 1

    # ---- backlog over time: open at the end of each bucket; opened vs closed per bucket ----
    backlog, opened, closed = [], [], []
    for b_start, b_end in spans:
        open_at = 0
        for f in real:
            d = _utc(f.detected_at)
            if not d or d > b_end or _sev(f.severity) == "info":
                continue
            r = _utc(f.resolved_at)
            if _status(f.status) in OPEN_STATUSES or (r and r > b_end):
                open_at += 1
        backlog.append(open_at)
        opened.append(sum(1 for f in real if _sev(f.severity) != "info" and (d := _utc(f.detected_at)) and b_start <= d < b_end))
        closed.append(sum(1 for f in resolved if (r := _utc(f.resolved_at)) and b_start <= r < b_end))

    # ---- SLA status and backlog age (open, non-info) ----
    sla = {sev: {"within": 0, "due_soon": 0, "overdue": 0} for sev in RISK_SEVERITIES}
    age = {sev: [0] * len(AGE_BUCKETS) for sev in RISK_SEVERITIES}
    ages_days = []
    overdue_items = []
    for f in open_items:
        sev = _sev(f.severity)
        if sev == "info":
            continue
        d = _utc(f.detected_at) or now
        age_days = max(0, (now - d).days)
        ages_days.append(age_days)
        for i, (lo, hi, _) in enumerate(AGE_BUCKETS):
            if age_days >= lo and (hi is None or age_days <= hi):
                age[sev][i] += 1
                break
        due = _utc(f.sla_due_at) or d + timedelta(days=SLA_DAYS[sev])
        if due < now:
            sla[sev]["overdue"] += 1
            overdue_items.append((sev, (now - due).days, f))
        elif due - now <= timedelta(days=7):
            sla[sev]["due_soon"] += 1
        else:
            sla[sev]["within"] += 1
    overdue_items.sort(key=lambda x: (RISK_SEVERITIES.index(x[0]), -x[1]))

    # ---- MTTR (resolved within the range) ----
    mttr: dict[str, Any] = {}
    all_fix_days = []
    for sev in RISK_SEVERITIES:
        fix_days = [
            (r - d).total_seconds() / 86400
            for f in resolved
            if _sev(f.severity) == sev and (r := _utc(f.resolved_at)) and (d := _utc(f.detected_at)) and r >= start and r >= d
        ]
        all_fix_days += fix_days
        mttr[sev] = {"count": len(fix_days), "mean_days": round(sum(fix_days) / len(fix_days), 1) if fix_days else None,
                     "median_days": round(median(fix_days), 1) if fix_days else None}

    # ---- scanner signal quality (all time, per engine) ----
    per_source: dict[str, Counter] = defaultdict(Counter)
    for f in findings:
        st = _status(f.status)
        bucket = "false_positive" if st in FP_STATUSES else "resolved" if st in RESOLVED_STATUSES else "accepted" if st in ACCEPTED_STATUSES else "open"
        per_source[str(f.source or "unknown")][bucket] += 1
    signal = []
    for source, c in per_source.items():
        total = sum(c.values())
        signal.append({
            "source": source,
            "label": ENGINE_LABELS.get(source, source),
            "total": total,
            "open": c["open"],
            "resolved": c["resolved"],
            "accepted": c["accepted"],
            "false_positive": c["false_positive"],
            "fp_rate": round(c["false_positive"] / total, 3) if total else 0,
        })
    signal.sort(key=lambda r: -r["total"])
    triaged = sum(r["false_positive"] + r["resolved"] + r["accepted"] for r in signal)

    # ---- scan activity ----
    scan_series = {"completed": [0] * len(spans), "failed": [0] * len(spans)}
    per_tool: dict[str, dict[str, Any]] = defaultdict(lambda: {"completed": 0, "failed": 0, "durations": []})
    for s in scans:
        created = _utc(s.created_at)
        st = _status(s.status)
        if created and created >= first and st in scan_series:
            scan_series[st][min(int((created - first) / step), len(spans) - 1)] += 1
        if created and created >= start and st in ("completed", "failed"):
            per_tool[s.tool][st] += 1
            a, b = _utc(s.started_at), _utc(s.finished_at)
            if st == "completed" and a and b and b >= a:
                per_tool[s.tool]["durations"].append((b - a).total_seconds())
    tools = [
        {
            "tool": tool,
            "label": ENGINE_LABELS.get(tool, tool),
            "completed": v["completed"],
            "failed": v["failed"],
            "success_rate": round(v["completed"] / (v["completed"] + v["failed"]), 3) if (v["completed"] + v["failed"]) else None,
            "median_minutes": round(median(v["durations"]) / 60, 1) if v["durations"] else None,
        }
        for tool, v in per_tool.items()
    ]
    tools.sort(key=lambda r: -(r["completed"] + r["failed"]))

    # ---- coverage: assets scanned in the last 30 days ----
    cutoff = now - timedelta(days=30)
    last_seen_by_token: dict[str, datetime] = {}
    for s in scans:
        when = _utc(s.finished_at) or _utc(s.created_at)
        if not when or _status(s.status) != "completed":
            continue
        raw = str(s.target or "").lower()
        host = (urlparse(raw).netloc if "://" in raw else raw).split(":")[0]
        for token in {raw, host}:
            if token and (token not in last_seen_by_token or when > last_seen_by_token[token]):
                last_seen_by_token[token] = when
    last_by_asset_id: dict[str, datetime] = {}
    for f in findings:
        if f.asset_id and (d := _utc(f.last_seen) or _utc(f.detected_at)):
            key = str(f.asset_id)
            if key not in last_by_asset_id or d > last_by_asset_id[key]:
                last_by_asset_id[key] = d
    coverage_rows = []
    for a in assets:
        candidates = [last_seen_by_token[t] for t in _host_tokens(a) if t in last_seen_by_token]
        if str(a.id) in last_by_asset_id:
            candidates.append(last_by_asset_id[str(a.id)])
        last = max(candidates) if candidates else None
        coverage_rows.append({"id": str(a.id), "name": a.asset_name or a.hostname or a.ip_address, "address": a.ip_address or a.hostname or a.url or "",
                              "criticality": a.criticality, "last_scanned": last.isoformat() if last else None,
                              "stale": not last or last < cutoff})
    coverage_rows.sort(key=lambda r: (not r["stale"], r["last_scanned"] or ""))
    covered = sum(1 for r in coverage_rows if not r["stale"])

    # ---- recurring issues, riskiest targets, categories, owners (open, non-info) ----
    issues: dict[str, dict[str, Any]] = {}
    targets: dict[str, dict[str, Any]] = {}
    categories: dict[str, Counter] = defaultdict(Counter)
    owners: dict[str, Counter] = defaultdict(Counter)
    for f in open_items:
        sev = _sev(f.severity)
        if sev == "info":
            continue
        name = _issue_name(f)
        target = target_of(f)
        e = issues.setdefault(name, {"name": name, "count": 0, "targets": set(), "severity": sev})
        e["count"] += 1
        e["targets"].add(target)
        if SEVERITIES.index(sev) < SEVERITIES.index(e["severity"]):
            e["severity"] = sev
        t = targets.setdefault(target, {"target": target, "score": 0.0, **{s: 0 for s in RISK_SEVERITIES}})
        t["score"] += SEVERITY_WEIGHT[sev]
        t[sev] += 1
        categories[str(f.category or "other")][sev] += 1
        owners[f.assigned_to or "Unassigned"][sev] += 1
    recurring = sorted(
        ({**v, "targets": len(v["targets"])} for v in issues.values()),
        key=lambda r: (-r["targets"], SEVERITIES.index(r["severity"]), -r["count"]),
    )[:10]
    riskiest = sorted(targets.values(), key=lambda r: -r["score"])[:10]
    for r in riskiest:
        r["score"] = round(r["score"], 1)

    total_sla = sum(sum(v.values()) for v in sla.values())
    overdue_total = sum(v["overdue"] for v in sla.values())
    return {
        "generated_at": now.isoformat(),
        "range_days": days,
        "bucket": "day" if step.days == 1 else "week",
        "labels": [b_start.date().isoformat() for b_start, _ in spans],
        "sla_policy_days": SLA_DAYS,
        "kpis": {
            "open_backlog": sum(1 for f in open_items if _sev(f.severity) != "info"),
            "overdue": overdue_total,
            "sla_compliance": round(1 - overdue_total / total_sla, 3) if total_sla else None,
            "mttr_days": round(sum(all_fix_days) / len(all_fix_days), 1) if all_fix_days else None,
            "resolved_in_range": len(all_fix_days),
            "fp_rate": round(sum(r["false_positive"] for r in signal) / sum(r["total"] for r in signal), 3) if signal else None,
            "triaged": triaged,
            "coverage": round(covered / len(coverage_rows), 3) if coverage_rows else None,
            "assets": len(coverage_rows),
            "assets_covered": covered,
            "median_age_days": round(median(ages_days)) if ages_days else None,
            "new_in_range": sum(sum(v) for v in detection.values()),
        },
        "detection": detection,
        "backlog": {"open": backlog, "opened": opened, "closed": closed},
        "sla": sla,
        "overdue": [
            {"id": str(f.id), "title": f.title, "severity": sev, "days_overdue": late, "target": target_of(f)}
            for sev, late, f in overdue_items[:8]
        ],
        "age": {"labels": [label for _, _, label in AGE_BUCKETS], "series": age},
        "mttr": mttr,
        "signal": signal,
        "scans": {"series": scan_series, "tools": tools},
        "coverage": coverage_rows[:12],
        "recurring": recurring,
        "riskiest": riskiest,
        "categories": [{"category": k, **{s: v[s] for s in RISK_SEVERITIES}, "total": sum(v.values())} for k, v in sorted(categories.items(), key=lambda kv: -sum(kv[1].values()))],
        "owners": [{"owner": k, **{s: v[s] for s in RISK_SEVERITIES}, "total": sum(v.values())} for k, v in sorted(owners.items(), key=lambda kv: -sum(kv[1].values()))][:8],
    }
