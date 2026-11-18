"""In-app notifications: findings assigned to a user, and new CVEs from the threat-intel feeds.

Every notification is real: it is created from an assignment someone made, or from an entry that
appeared in CISA KEV, Microsoft's security update guide or NVD. Nothing is generated for display.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.finding import Finding
from app.models.notification import Notification
from app.models.user import User

log = logging.getLogger(__name__)

CHECK_SECONDS = int(os.getenv("CVE_NOTIFY_INTERVAL_SECONDS", "1800"))
NVD_MIN_CVSS = float(os.getenv("CVE_NOTIFY_NVD_MIN_CVSS", "9.0"))
MSRC_FRESH_DAYS = 3
KEV_FRESH_DAYS = 2


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _recipients(db: Session) -> list[str]:
    q = db.query(User.username)
    if hasattr(User, "is_active"):
        q = q.filter(User.is_active.is_(True))
    return [u for (u,) in q.all()]


def notify(db: Session, usernames: Iterable[str], *, kind: str, ref: str, title: str, body: str = "",
           severity: str | None = None, link: str | None = None, data: dict | None = None) -> int:
    """Create one notification per user, skipping any user who already has this (kind, ref)."""
    rows = [{"username": u, "kind": kind, "ref": ref, "title": title[:240], "body": body[:2000], "severity": severity,
             "link": link, "data": data or {}} for u in dict.fromkeys(usernames) if u]
    if not rows:
        return 0
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        stmt = pg_insert(Notification).values(rows).on_conflict_do_nothing(constraint="uq_notification_user_kind_ref")
        result = db.execute(stmt)
        db.commit()
        return result.rowcount or 0
    created = 0
    for row in rows:
        if not db.query(Notification).filter_by(username=row["username"], kind=kind, ref=ref).first():
            db.add(Notification(**row))
            created += 1
    db.commit()
    return created


# ---------------------------------------------------------------------------------------------
# Finding assigned
# ---------------------------------------------------------------------------------------------

def notify_finding_assigned(finding: Finding, assignee: str, assigned_by: str, target: str = "") -> None:
    """Uses its own session so it never commits or rolls back the caller's request transaction."""
    if not assignee or assignee == assigned_by:
        return  # don't notify people about their own action
    sev = (finding.severity or "info").lower()
    db = SessionLocal()
    try:
        _notify_assigned(db, finding, assignee, assigned_by, target, sev)
    finally:
        db.close()


def _notify_assigned(db: Session, finding: Finding, assignee: str, assigned_by: str, target: str, sev: str) -> None:
    notify(
        db, [assignee], kind="finding_assigned",
        # Re-assigning the same finding to the same person later is a new event: include the time.
        ref=f"{finding.id}:{_now().strftime('%Y%m%d%H%M%S')}",
        title=f"Assigned to you: {finding.title}",
        body=f"{sev.capitalize()} finding{f' on {target}' if target else ''}, assigned by {assigned_by}.",
        severity=sev, link=f"/findings/{finding.id}",
        data={"finding_id": str(finding.id), "assigned_by": assigned_by},
    )


# ---------------------------------------------------------------------------------------------
# New CVEs (same sources as the Threat Intelligence "Today" panel)
# ---------------------------------------------------------------------------------------------

def _environment_cves(db: Session) -> set[str]:
    from app.services.intel import CVE_RE

    cves: set[str] = set()
    for (text,) in db.query(Finding.cve_id).filter(Finding.cve_id.isnot(None)).all():
        cves |= {c.upper() for c in CVE_RE.findall(str(text or ""))}
    return cves


def check_new_cves(db: Session) -> dict[str, int]:
    """Notify every active user about CVEs that just appeared in the feeds. Idempotent."""
    from app.services.intel import kev_catalog
    from app.services.intel_today import _cached, _microsoft, _nvd

    users = _recipients(db)
    if not users:
        return {}
    env = _environment_cves(db)
    stats = {"kev": 0, "microsoft": 0, "nvd_digest": 0, "nvd_in_env": 0}
    today = _now().date()

    # 1) CISA KEV: newly added = exploited in the wild right now. One notification each.
    kev = kev_catalog()
    cutoff = (today - timedelta(days=KEV_FRESH_DAYS - 1)).isoformat()
    for cve, v in (kev.get("by_cve") or {}).items():
        if (v.get("dateAdded") or "") < cutoff:
            continue
        mine = cve in env
        stats["kev"] += notify(
            db, users, kind="new_cve", ref=cve,
            title=f"{cve} added to CISA KEV{' — affects your findings' if mine else ''}",
            body=(f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}. "
                  f"Exploited in the wild{'; used in ransomware campaigns' if str(v.get('knownRansomwareCampaignUse', '')).lower() == 'known' else ''}. "
                  f"Federal due date {v.get('dueDate', '—')}.").strip(),
            severity="critical", link=f"/threat-intelligence?cve={cve}",
            data={"source": "CISA KEV", "cve": cve, "in_environment": mine, "date_added": v.get("dateAdded")},
        )

    # 2) Microsoft: exploited or publicly disclosed CVEs in a release that is still fresh.
    ms = _cached("msrc", 3600, _microsoft)
    released = str((ms or {}).get("released") or "")[:10] if isinstance(ms, dict) else ""
    if released and released >= (today - timedelta(days=MSRC_FRESH_DAYS)).isoformat():
        for group, label in (("exploited", "exploited in the wild"), ("disclosed", "publicly disclosed")):
            for row in ms.get(group, []):
                cve = (row.get("cve") or "").upper()
                if not cve:
                    continue
                mine = cve in env
                cvss = f", CVSS {row['cvss']}" if row.get("cvss") else ""
                stats["microsoft"] += notify(
                    db, users, kind="new_cve", ref=cve,
                    title=f"Microsoft {cve} {label}{' — affects your findings' if mine else ''}",
                    body=f"{row.get('title') or ''}. {row.get('severity') or 'Unrated'}{cvss}. {ms.get('title') or ''}",
                    severity="critical" if row.get("exploited") else "high", link=f"/threat-intelligence?cve={cve}",
                    data={"source": "Microsoft MSRC", "cve": cve, "in_environment": mine, "release": ms.get("release")},
                )

    # 3) NVD: one daily digest for critical CVEs, plus one each for any that match your findings.
    nvd = _cached("nvd24", 1800, _nvd)
    top = [r for r in (nvd.get("top", []) if isinstance(nvd, dict) else []) if (r.get("cvss") or 0) >= NVD_MIN_CVSS]
    if top:
        stats["nvd_digest"] += notify(
            db, users, kind="cve_digest", ref=f"nvd-{today.isoformat()}",
            title=f"{len(top)} new critical CVE{'s' if len(top) != 1 else ''} on NVD today (CVSS ≥ {NVD_MIN_CVSS:g})",
            body=", ".join(r.get("cve") or "" for r in top[:6]) + (" …" if len(top) > 6 else ""),
            severity="high", link="/threat-intelligence?today=nvd",
            data={"source": "NVD", "count": len(top), "cves": [r.get("cve") for r in top[:25]]},
        )
        for r in top:
            cve = (r.get("cve") or "").upper()
            if cve and cve in env:
                stats["nvd_in_env"] += notify(
                    db, users, kind="new_cve", ref=cve,
                    title=f"{cve} (CVSS {r.get('cvss')}) published — affects your findings",
                    body=(r.get("description") or r.get("summary") or "")[:400],
                    severity="critical", link=f"/threat-intelligence?cve={cve}",
                    data={"source": "NVD", "cve": cve, "in_environment": True},
                )
    return stats


# ---------------------------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------------------------

_started = False


def _loop() -> None:
    time.sleep(60)  # let the API finish starting
    while True:
        db = SessionLocal()
        try:
            stats = check_new_cves(db)
            if any(stats.values()):
                log.info("CVE notifications created: %s", stats)
        except Exception as exc:  # feeds offline etc.: try again next round
            log.warning("CVE notification check failed: %s", exc)
            db.rollback()
        finally:
            db.close()
        time.sleep(CHECK_SECONDS)


def start_cve_notifier() -> None:
    global _started
    if _started or os.getenv("CVE_NOTIFY_ENABLED", "1") != "1":
        return
    _started = True
    threading.Thread(target=_loop, daemon=True, name="cve-notifier").start()


# ---------------------------------------------------------------------------------------------
# Read API helpers
# ---------------------------------------------------------------------------------------------

def serialize(n: Notification) -> dict[str, Any]:
    return {
        "id": str(n.id), "kind": n.kind, "title": n.title, "body": n.body, "severity": n.severity,
        "link": n.link, "data": n.data or {}, "created_at": n.created_at.isoformat() if n.created_at else None,
        "read": n.read_at is not None,
    }
