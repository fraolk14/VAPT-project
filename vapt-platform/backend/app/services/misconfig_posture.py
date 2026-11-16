"""Configuration posture built from real findings.

The network, web and endpoint-agent engines already report configuration problems (missing
security headers, cleartext services, exposed admin consoles, CIS hardening failures, ...).
This module picks those findings out, groups them into control families and per-target views.
Software vulnerabilities (CVE-only), injection flaws and Shadow IT / software inventory items
are left to their own pages.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.analytics import _target_of, _utc

SEVERITIES = ["critical", "high", "medium", "low", "info"]
OPEN = {"open", "in_progress", "reopened", "new", "triaged"}
RESOLVED = {"resolved", "closed", "fixed", "remediated"}

# (key, label, keywords). Order matters: the first family whose keywords match wins.
FAMILIES: list[tuple[str, str, tuple[str, ...]]] = [
    ("os-hardening", "OS hardening (CIS)", (
        "smbv1", "llmnr", "nbt-ns", "unquoted", "uac ", "user account control", "defender", "firewall disabled",
        "firewall is disabled", "autorun", "autoplay", "guest account", "password policy", "lockout policy",
        "nla ", "network level authentication", "powershell v2", "wdigest", "lm hash", "ntlmv1", "bitlocker",
        "screen lock", "audit policy",
    )),
    ("auth", "Authentication & access", (
        "default credential", "default password", "anonymous", "without authentication", "unauthenticated",
        "no authentication", "authentication challenge", "weak password", "login form over http", "brute force",
    )),
    ("cors-cookies", "CORS & cookies", (
        "cors", "access-control-allow-origin", "cookie", "samesite", "httponly",
    )),
    ("headers", "HTTP security headers", (
        "content-security-policy", "content security policy", "csp", "clickjacking", "x-frame-options",
        "mime sniffing", "x-content-type-options", "referrer-policy", "permissions-policy", "security header",
        "header not set", "header missing",
    )),
    ("transport", "Encryption in transit", (
        "cleartext", "plaintext", "tls", "ssl", "hsts", "strict-transport", "certificate", "cipher",
        "unencrypted", "http without https", "insecure transport",
    )),
    ("exposed-services", "Exposed services & admin", (
        "service exposed", "telnet", "rdp", "remote desktop", "smb service", "netbios", "vnc", "redis", "mongodb",
        "elasticsearch", "memcached", "docker", "rpcbind", "ftp", "snmp", "database port", "admin dashboard",
        "administrative", "admin panel", "admin interface", "kibana", "server-status", "server status",
        "console", "debug", "actuator", "phpmyadmin", "management interface", "jenkins", "postgres", "mysql",
        "mssql", "sql server", "oracle", "open port",
    )),
    ("disclosure", "Information disclosure", (
        ".git", ".ds_store", "swagger", "openapi", "graphql", "robots.txt", "backup", "dump", ".env",
        "configuration file", "configuration json", "config file", "version disclosure", "server banner",
        "directory listing", "directory index", "stack trace", "error message", "phpinfo", "x-powered-by",
        "source map", "information disclosure", "sensitive file", "exposed",
    )),
]
FAMILY_LABEL = {key: label for key, label, _ in FAMILIES}

_NOT_CONFIG = re.compile(
    r"sql injection|sqli|cross[- ]site scripting|\bxss\b|command injection|path traversal|remote code execution|"
    r"\brce\b|deserializ|ssrf|xxe|buffer overflow|outdated|end[- ]of[- ]life|vulnerable version",
    re.I,
)
_TITLE_NOISE = re.compile(r"\s+(on|at|for)\s+(port\s+)?\d+.*$", re.I)
_EXPOSED_SERVICE = re.compile(r"^exposed (\S+) service$", re.I)
_SERVICE_NAMES = {"postgresql": "PostgreSQL", "mongodb": "MongoDB", "mysql": "MySQL", "nginx": "nginx", "rpcbind": "rpcbind",
                  "redis": "Redis", "apache": "Apache", "telnet": "Telnet", "elasticsearch": "Elasticsearch"}


def classify(finding: Finding) -> str | None:
    """Return the control family key for a configuration finding, or None if it isn't one."""
    category = str(finding.category or "").lower()
    if "shadow" in category or "software" in category:
        return None
    title = str(finding.title or "")
    if _NOT_CONFIG.search(title) or title.lower().startswith("no ") or str(finding.severity or "").lower() == "info":
        return None
    cve = str(finding.cve_id or "").upper()
    if cve.startswith("CIS") or (finding.source == "endpoint-agent" and "misconfig" in category):
        return "os-hardening"
    text = f" {title.lower()} {category} "
    if _EXPOSED_SERVICE.match(title.strip()):
        return "exposed-services"
    for key, _, keywords in FAMILIES:
        if any(k in text for k in keywords):
            return key
    if "misconfig" in category:
        return "disclosure" if "expos" in text else "os-hardening"
    return None


def _issue_title(title: str) -> str:
    """Normalise titles so engines that word the same issue differently are grouped together."""
    clean = _TITLE_NOISE.sub("", title.strip())[:140] or title[:140]
    m = _EXPOSED_SERVICE.match(clean)
    if m:
        name = m.group(1).lower()
        name = _SERVICE_NAMES.get(name, name.upper() if len(name) <= 4 else name.capitalize())
        return f"{name} service exposed"
    return clean


def build_posture(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    findings = db.query(Finding).all()
    assets = db.query(Asset).all()
    scans = db.query(Scan).all()
    asset_names = {str(a.id): (a.hostname or a.ip_address or a.asset_name or "") for a in assets}
    scan_targets = {str(s.id): str(s.target or "") for s in scans}

    families: dict[str, dict[str, Any]] = {
        key: {"key": key, "label": label, "open": 0, "targets": set(), **{s: 0 for s in SEVERITIES}} for key, label, _ in FAMILIES
    }
    targets: dict[str, dict[str, Any]] = {}
    issues: dict[tuple[str, str], dict[str, Any]] = {}
    cis: dict[str, dict[str, Any]] = {}
    fixed_30d = 0

    for f in findings:
        family = classify(f)
        if not family:
            continue
        status = str(f.status or "open").lower()
        if status in RESOLVED:
            resolved = _utc(f.resolved_at)
            if resolved and resolved >= now - timedelta(days=30):
                fixed_30d += 1
            continue
        if status not in OPEN:
            continue
        sev = str(f.severity or "info").lower()
        sev = sev if sev in SEVERITIES else "info"
        target = _target_of(f, asset_names, scan_targets)

        fam = families[family]
        fam["open"] += 1
        fam[sev] += 1
        fam["targets"].add(target)

        t = targets.setdefault(target, {"target": target, "open": 0, "families": Counter(), **{s: 0 for s in SEVERITIES}})
        t["open"] += 1
        t[sev] += 1
        t["families"][family] += 1

        title = _issue_title(f.title or "Untitled")
        issue = issues.setdefault((family, title.lower()), {
            "key": f"{family}:{title.lower()}",
            "title": title,
            "family": family,
            "family_label": FAMILY_LABEL[family],
            "severity": sev,
            "count": 0,
            "targets": set(),
            "sources": set(),
            "control": None,
            "remediation": None,
            "evidence": None,
            "first_seen": None,
            "last_seen": None,
        })
        issue["count"] += 1
        issue["targets"].add(target)
        issue["sources"].add(str(f.source or "scanner"))
        if SEVERITIES.index(sev) < SEVERITIES.index(issue["severity"]):
            issue["severity"] = sev
        cve = str(f.cve_id or "")
        if cve.upper().startswith("CIS"):
            issue["control"] = cve
        if not issue["remediation"] and f.remediation:
            issue["remediation"] = f.remediation
        if not issue["evidence"] and f.evidence:
            issue["evidence"] = str(f.evidence)[:600]
        detected = _utc(f.detected_at)
        seen = _utc(f.last_seen) or detected
        if detected and (issue["first_seen"] is None or detected < issue["first_seen"]):
            issue["first_seen"] = detected
        if seen and (issue["last_seen"] is None or seen > issue["last_seen"]):
            issue["last_seen"] = seen

        if family == "os-hardening":
            control = cve if cve.upper().startswith("CIS") else "—"
            c = cis.setdefault(title.lower(), {"title": title, "control": control, "severity": sev, "endpoints": set()})
            c["endpoints"].add(target)
            if SEVERITIES.index(sev) < SEVERITIES.index(c["severity"]):
                c["severity"] = sev

    issue_rows = sorted(
        (
            {
                **i,
                "targets": sorted(i["targets"]),
                "target_count": len(i["targets"]),
                "sources": sorted(i["sources"]),
                "first_seen": i["first_seen"].isoformat() if i["first_seen"] else None,
                "last_seen": i["last_seen"].isoformat() if i["last_seen"] else None,
            }
            for i in issues.values()
        ),
        key=lambda r: (SEVERITIES.index(r["severity"]), -r["target_count"], -r["count"], r["title"]),
    )
    weight = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}
    target_rows = sorted(targets.values(), key=lambda t: -sum(t[s] * weight[s] for s in SEVERITIES))
    top_targets = target_rows[:12]
    family_rows = [{**v, "targets": len(v["targets"])} for v in families.values()]

    open_total = sum(f["open"] for f in family_rows)
    return {
        "generated_at": now.isoformat(),
        "kpis": {
            "open": open_total,
            "urgent": sum(f["critical"] + f["high"] for f in family_rows),
            "targets": len(targets),
            "issue_types": len(issue_rows),
            "families_failing": sum(1 for f in family_rows if f["open"]),
            "cis_failing": len(cis),
            "fixed_30d": fixed_30d,
        },
        "families": family_rows,
        "matrix": {
            "rows": [{"key": key, "label": label} for key, label, _ in FAMILIES],
            "cols": [t["target"] for t in top_targets],
            "values": [[t["families"].get(key, 0) for t in top_targets] for key, _, _ in FAMILIES],
        },
        "targets": [
            {"target": t["target"], "open": t["open"], **{s: t[s] for s in SEVERITIES},
             "families": {FAMILY_LABEL[k]: v for k, v in t["families"].most_common()}}
            for t in top_targets
        ],
        "issues": issue_rows[:300],
        "cis": sorted(
            ({**c, "endpoints": sorted(c["endpoints"]), "endpoint_count": len(c["endpoints"])} for c in cis.values()),
            key=lambda c: (SEVERITIES.index(c["severity"]), -c["endpoint_count"]),
        ),
    }
