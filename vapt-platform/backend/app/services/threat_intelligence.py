from __future__ import annotations

import csv
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import io
import os
import socket
from typing import Iterable
from urllib.parse import urlparse

import requests

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.operations import MonitoringEvent, SecurityIncident
from app.models.scan import Scan

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

KEV_SAMPLE = {
    "CVE-2021-44228",
    "CVE-2023-23397",
    "CVE-2024-3400",
    "CVE-2023-3519",
}

COUNTRY_RULES = {
    "Russia": ["russia", "moscow", ".ru"],
    "United States": ["usa", "united states", "us-", "new york", "california", ".gov", ".com"],
    "United Kingdom": ["united kingdom", "uk", "london", ".co.uk"],
    "Germany": ["germany", "berlin", ".de"],
    "France": ["france", "paris", ".fr"],
    "Netherlands": ["netherlands", "amsterdam", ".nl"],
    "India": ["india", "mumbai", "bangalore", ".in"],
    "Singapore": ["singapore", ".sg"],
    "Japan": ["japan", "tokyo", ".jp"],
    "China": ["china", "beijing", ".cn"],
    "Australia": ["australia", "sydney", ".au"],
    "Brazil": ["brazil", "sao paulo", ".br"],
    "Canada": ["canada", "toronto", ".ca"],
    "United Arab Emirates": ["uae", "dubai", "abu dhabi"],
    "South Africa": ["south africa", "johannesburg", ".za"],
    "Ethiopia": ["ethiopia", "addis", ".et"],
    "Kenya": ["kenya", "nairobi", ".ke"],
    "Nigeria": ["nigeria", "lagos", ".ng"],
    "Egypt": ["egypt", "cairo", ".eg"],
    "Saudi Arabia": ["saudi", "riyadh", ".sa"],
    "Turkey": ["turkey", "istanbul", ".tr"],
    "Israel": ["israel", "tel aviv", ".il"],
    "Italy": ["italy", "milan", ".it"],
    "Spain": ["spain", "madrid", ".es"],
    "Sweden": ["sweden", "stockholm", ".se"],
    "Poland": ["poland", "warsaw", ".pl"],
    "Mexico": ["mexico", ".mx"],
    "Argentina": ["argentina", ".ar"],
    "Chile": ["chile", ".cl"],
    "South Korea": ["korea", "seoul", ".kr"],
    "Indonesia": ["indonesia", "jakarta", ".id"],
    "Malaysia": ["malaysia", ".my"],
    "Thailand": ["thailand", "bangkok", ".th"],
    "Philippines": ["philippines", "manila", ".ph"],
}

COUNTRY_REGIONS = {
    "Russia": "Europe",
    "United States": "North America",
    "Canada": "North America",
    "Brazil": "South America",
    "United Kingdom": "Europe",
    "Germany": "Europe",
    "France": "Europe",
    "Netherlands": "Europe",
    "South Africa": "Africa",
    "Ethiopia": "Africa",
    "United Arab Emirates": "Middle East",
    "India": "Asia",
    "Singapore": "Asia",
    "Japan": "Asia",
    "China": "Asia",
    "Australia": "Oceania",
    "Kenya": "Africa",
    "Nigeria": "Africa",
    "Egypt": "Africa",
    "Saudi Arabia": "Middle East",
    "Turkey": "Middle East",
    "Israel": "Middle East",
    "Italy": "Europe",
    "Spain": "Europe",
    "Sweden": "Europe",
    "Poland": "Europe",
    "Mexico": "North America",
    "Argentina": "South America",
    "Chile": "South America",
    "South Korea": "Asia",
    "Indonesia": "Asia",
    "Malaysia": "Asia",
    "Thailand": "Asia",
    "Philippines": "Asia",
}

GLOBAL_TARGET_COUNTRIES = [
    "United States",
    "Germany",
    "Japan",
    "United Kingdom",
    "India",
    "Brazil",
    "Canada",
    "France",
    "Netherlands",
    "Australia",
    "Singapore",
    "South Korea",
    "Italy",
    "Spain",
    "Sweden",
    "Poland",
    "Mexico",
    "Argentina",
    "Chile",
    "South Africa",
    "Kenya",
    "Nigeria",
    "Egypt",
    "United Arab Emirates",
    "Saudi Arabia",
    "Turkey",
    "Israel",
    "Indonesia",
    "Malaysia",
    "Thailand",
    "Philippines",
    "Ethiopia",
]

SAMPLE_COMPANIES_BY_COUNTRY = {
    "United States": ["Apex Health Cloud", "Northwind Bank", "Liberty Retail"],
    "Germany": ["Rhine Industrial Systems", "Berlin CloudWorks"],
    "Japan": ["Sakura Robotics", "Tokyo FinTech Exchange"],
    "United Kingdom": ["Albion Insurance", "London SaaS Grid"],
    "India": ["Bharat Payments", "Mumbai HealthNet"],
    "Brazil": ["Sao Paulo Retail Group", "Atlas Telecom"],
    "Canada": ["Maple Energy", "Toronto Data Exchange"],
    "France": ["Paris Logistics Cloud", "HexaBank"],
    "Netherlands": ["Amsterdam Hosting Cooperative", "Canal Health Systems"],
    "Australia": ["Southern Cross Mining", "Sydney EduCloud"],
    "Ethiopia": ["Addis Digital Services", "Ethio Retail Network"],
}

SOURCE_COUNTRY_BY_ATTACK = {
    "SQL Injection": "China",
    "Cross-Site Scripting": "United States",
    "Remote Code Execution": "Russia",
    "Credential Attack": "Netherlands",
    "Malware Delivery": "Germany",
    "Command and Control": "Singapore",
    "Scanning Activity": "United States",
    "TLS Weakness": "France",
    "Unauthorized Software": "Brazil",
    "Suspicious Activity": "United Kingdom",
}

MALWARE_KEYWORDS = {
    "Ransomware": ["ransomware", "lockbit", "blackcat", "encrypt"],
    "InfoStealer": ["stealer", "infostealer", "credential theft", "cookie theft"],
    "Botnet": ["botnet", "mirai", "ddos"],
    "Webshell": ["webshell", "shell upload"],
    "Trojan": ["trojan", "loader", "dropper"],
}

DEFAULT_PRIVATE_NETWORK_COUNTRY = os.getenv("DEFAULT_PRIVATE_NETWORK_COUNTRY", "Ethiopia")
URLHAUS_RECENT_FEED_URL = os.getenv("URLHAUS_RECENT_FEED_URL", "https://urlhaus.abuse.ch/downloads/csv_recent/")
URLHAUS_RECENT_LIMIT = int(os.getenv("URLHAUS_RECENT_LIMIT", "360"))

_geoip_cache: dict[str, str] = {}
_urlhaus_cache: dict[str, object] = {"fetched_at": None, "rows": []}


def _mitre_tags(finding: Finding) -> list[str]:
    metadata = finding.finding_metadata or {}
    text = " ".join(
        [
            finding.title or "",
            finding.evidence or "",
            finding.remediation or "",
            str(metadata.get("risk") or ""),
            str(metadata.get("attack") or ""),
            str(metadata.get("reference") or ""),
            str(metadata.get("cwe_id") or ""),
        ]
    ).lower()
    tags: list[str] = []
    if "xss" in text:
        tags.append("T1189 Drive-by Compromise")
    if "sql" in text or "injection" in text:
        tags.append("T1190 Exploit Public-Facing Application")
    if "csp" in text or "content security policy" in text or "x-frame-options" in text or "clickjacking" in text:
        tags.append("T1190 Exploit Public-Facing Application")
    if "csrf" in text:
        tags.append("T1189 Drive-by Compromise")
    if "directory listing" in text or "path traversal" in text:
        tags.append("T1083 File and Directory Discovery")
    if "cookie" in text or "session" in text or "anti-clickjacking" in text:
        tags.append("T1539 Steal Web Session Cookie")
    if "secret" in text or "credential" in text or "auth" in text:
        tags.append("T1552 Unsecured Credentials")
    if finding.category == "network":
        tags.append("T1046 Network Service Discovery")
    return list(dict.fromkeys(tags))


def _exploit_flags(finding: Finding) -> tuple[bool, bool, str]:
    severity = (finding.severity or "info").lower()
    title = (finding.title or "").lower()
    exploit_available = bool(
        finding.cve_id
        or severity in {"critical", "high"}
        or any(keyword in title for keyword in ("xss", "sql", "injection", "secret"))
    )
    actively_exploited = bool(finding.cve_id in KEV_SAMPLE or severity == "critical")
    if actively_exploited:
        indicator = "Actively exploited"
    elif exploit_available:
        indicator = "Exploit path likely"
    else:
        indicator = "Monitoring"
    return exploit_available, actively_exploited, indicator


def build_threat_feed(findings: Iterable[Finding], scan_map: dict[str, Scan]) -> list[dict]:
    enriched = []
    for finding in findings:
        exploit_available, actively_exploited, indicator = _exploit_flags(finding)
        scan = scan_map.get(str(finding.scan_id))
        references = ["https://nvd.nist.gov/", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
        feed_sources = ["NVD", "CISA KEV"]
        if finding.cve_id:
            references.insert(0, f"https://nvd.nist.gov/vuln/detail/{finding.cve_id}")
        metadata = finding.finding_metadata or {}
        raw_reference = metadata.get("reference")
        if isinstance(raw_reference, str) and raw_reference.strip():
            references.extend([item.strip() for item in raw_reference.splitlines() if item.strip().startswith("http")])
        if _mitre_tags(finding):
            references.append("https://attack.mitre.org/")
            feed_sources.append("MITRE ATT&CK")
        if finding.source == "zap":
            feed_sources.append("OWASP Top 10")
            references.append("https://owasp.org/www-project-top-ten/")
        if exploit_available:
            references.append("https://www.exploit-db.com/")
            feed_sources.append("Exploit-DB")

        enriched.append(
            {
                "finding_id": str(finding.id),
                "title": finding.title,
                "cve_id": finding.cve_id,
                "severity": finding.severity or "info",
                "source": finding.source,
                "target": scan.target if scan else "unknown",
                "cvss_score": finding.cvss_score,
                "exploit_available": exploit_available,
                "actively_exploited": actively_exploited,
                "exploit_indicator": indicator,
                "mitre_attack": _mitre_tags(finding),
                "references": references,
                "feed_sources": list(dict.fromkeys(feed_sources)),
            }
        )

    enriched.sort(
        key=lambda item: (
            item["actively_exploited"],
            item["exploit_available"],
            SEVERITY_WEIGHT.get(str(item["severity"]).lower(), 0),
            item["cvss_score"] or 0,
        ),
        reverse=True,
    )
    return enriched


def threat_intel_summary(feed: list[dict]) -> dict:
    by_severity = Counter(item["severity"] for item in feed)
    by_source = Counter(item["source"] for item in feed)
    mitre_coverage = Counter(tag for item in feed for tag in item["mitre_attack"])
    reference_coverage = Counter(source for item in feed for source in item["feed_sources"])
    return {
        "total_enriched": len(feed),
        "actively_exploited": sum(1 for item in feed if item["actively_exploited"]),
        "exploit_available": sum(1 for item in feed if item["exploit_available"]),
        "by_severity": dict(by_severity),
        "by_source": dict(by_source),
        "mitre_coverage": dict(mitre_coverage.most_common(8)),
        "reference_coverage": dict(reference_coverage),
        "top_feed": feed[:10],
    }


def filter_threat_feed(
    feed: list[dict],
    *,
    severity: str | None = None,
    source: str | None = None,
    exploited_only: bool = False,
) -> list[dict]:
    filtered = feed
    if severity:
        filtered = [item for item in filtered if item["severity"] == severity]
    if source:
        filtered = [item for item in filtered if item["source"] == source]
    if exploited_only:
        filtered = [item for item in filtered if item["actively_exploited"]]
    return filtered


def _normalize_misp_event(item: dict, base_url: str, event_id: str | None = None) -> dict:
    event = item.get("Event", item) if isinstance(item, dict) else {}
    tags = []
    for tag in event.get("Tag", []) or []:
        if isinstance(tag, dict):
            value = tag.get("name")
            if value:
                tags.append(value)
    attributes = event.get("Attribute", []) or []
    orgc = event.get("Orgc", {}) if isinstance(event.get("Orgc"), dict) else {}
    threat_level_map = {"1": "high", "2": "medium", "3": "low", "4": "undefined"}
    resolved_id = str(event.get("id") or event_id or "")
    analysis = event.get("analysis")
    attribute_summary = ", ".join(
        filter(
            None,
            [
                str(attribute.get("comment") or attribute.get("category") or attribute.get("type") or "").strip()
                for attribute in attributes[:3]
                if isinstance(attribute, dict)
            ],
        )
    )
    description = (
        event.get("comment")
        or event.get("analysis")
        or event.get("threat_actor")
        or attribute_summary
        or "Feed event published by the source MISP instance."
    )
    if description in {0, "0"}:
        description = "Feed event published by the source MISP instance."
    modified = event.get("timestamp")
    return {
        "id": resolved_id,
        "name": event.get("info") or "Unnamed MISP event",
        "description": description,
        "modified": None if modified in {None, ""} else str(modified),
        "created": None if event.get("date") in {None, ""} else str(event.get("date")),
        "author_name": orgc.get("name"),
        "indicator_count": int(event.get("attribute_count") or len(attributes)),
        "tags": tags,
        "adversary": event.get("threat_actor"),
        "tlp": next((tag for tag in tags if tag.lower().startswith("tlp:")), None),
        "threat_level": threat_level_map.get(str(event.get("threat_level_id") or ""), "unknown"),
        "references": [base_url],
        "url": f"{base_url.rsplit('/', 1)[0]}/events/view/{resolved_id}" if resolved_id else base_url,
    }


def fetch_misp_events(limit: int = 5) -> tuple[str, list[dict]]:
    base_url = os.getenv("MISP_FEED_URL", "").strip().rstrip("/")
    api_key = os.getenv("MISP_API_KEY", "").strip()
    verify_ssl = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"
    if not base_url:
        return "not_configured", []

    try:
        headers = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = api_key
        response = requests.get(
            base_url,
            headers=headers,
            timeout=10,
            verify=verify_ssl,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return "unavailable", []

    if isinstance(payload, dict) and isinstance(payload.get("response"), list):
        results = payload.get("response", [])
        return "connected", [_normalize_misp_event(item, base_url) for item in results[:limit]]
    if isinstance(payload, dict) and payload and all(isinstance(value, dict) for value in payload.values()):
        items = list(payload.items())[:limit]
        return "connected", [_normalize_misp_event(item, base_url, event_id=event_id) for event_id, item in items]
    elif isinstance(payload, list):
        results = payload
        return "connected", [_normalize_misp_event(item, base_url) for item in results[:limit]]
    else:
        return "unavailable", []


def _isoformat(value: datetime | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (TypeError, ValueError):
            return datetime.now(timezone.utc)


def _text_blob(*parts) -> str:
    return " ".join(str(part or "") for part in parts).lower()


def infer_country(value: str | None, fallback: str = "United States") -> str:
    text = _text_blob(value)
    if not text:
        return fallback
    for country, markers in COUNTRY_RULES.items():
        if any(marker in text for marker in markers):
            return country
    return fallback


def _extract_host(target: str | None) -> str | None:
    if not target:
        return None
    text = str(target).strip()
    if not text:
        return None
    if "://" in text:
        try:
            return urlparse(text).hostname
        except Exception:
            return None
    return text.split("/")[0].split(":")[0]


def _resolve_country_from_host(host: str | None) -> str | None:
    if not host:
        return None
    normalized = host.strip().lower()
    if not normalized:
        return None
    if normalized in _geoip_cache:
        return _geoip_cache[normalized]

    try:
        ipaddress.ip_address(normalized)
        ip_value = normalized
    except ValueError:
        try:
            ip_value = socket.gethostbyname(normalized)
        except OSError:
            ip_value = None

    if not ip_value:
        country = infer_country(host, fallback="")
        if country:
            _geoip_cache[normalized] = country
            return country
        return None

    try:
        if ipaddress.ip_address(ip_value).is_private:
            _geoip_cache[normalized] = DEFAULT_PRIVATE_NETWORK_COUNTRY
            return DEFAULT_PRIVATE_NETWORK_COUNTRY
    except ValueError:
        pass

    try:
        response = requests.get(f"https://ipwho.is/{ip_value}", timeout=8)
        response.raise_for_status()
        payload = response.json()
        country = payload.get("country") if payload.get("success", True) else None
        if country:
            _geoip_cache[normalized] = country
            return country
    except Exception:
        pass

    country = infer_country(host, fallback="")
    if country:
        _geoip_cache[normalized] = country
        return country
    return None


def fetch_urlhaus_recent(limit: int = URLHAUS_RECENT_LIMIT) -> tuple[str, list[dict]]:
    cached_rows = _urlhaus_cache.get("rows") or []
    fetched_at = _urlhaus_cache.get("fetched_at")
    if isinstance(fetched_at, datetime) and (datetime.now(timezone.utc) - fetched_at) < timedelta(minutes=10) and cached_rows:
        return "connected", cached_rows[:limit]

    try:
        response = requests.get(URLHAUS_RECENT_FEED_URL, timeout=20)
        response.raise_for_status()
        lines = [line for line in response.text.splitlines() if line and not line.startswith("#")]
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        rows = []
        for index, row in enumerate(reader):
            if index >= limit:
                break
            rows.append(row)
        _urlhaus_cache["fetched_at"] = datetime.now(timezone.utc)
        _urlhaus_cache["rows"] = rows
        return "connected", rows
    except Exception:
        return "unavailable", []


def _infer_attack_type(*parts) -> str:
    text = _text_blob(*parts)
    if "sql" in text or "injection" in text:
        return "SQL Injection"
    if "xss" in text or "cross-site" in text:
        return "Cross-Site Scripting"
    if "csrf" in text or "session" in text or "credential" in text or "auth" in text:
        return "Credential Attack"
    if "rce" in text or "remote code" in text or "command execution" in text:
        return "Remote Code Execution"
    if "tls" in text or "cipher" in text or "ssl" in text:
        return "TLS Weakness"
    if "malware" in text or "loader" in text or "payload" in text:
        return "Malware Delivery"
    if "software" in text or "unauthorized" in text:
        return "Unauthorized Software"
    if "scan" in text or "probe" in text or "discovery" in text:
        return "Scanning Activity"
    return "Suspicious Activity"


def _infer_malware_type(*parts) -> str | None:
    text = _text_blob(*parts)
    for malware_type, markers in MALWARE_KEYWORDS.items():
        if any(marker in text for marker in markers):
            return malware_type
    return None


def _infer_industry(asset: Asset | None, target: str | None, metadata: dict | None = None) -> str:
    metadata = metadata or {}
    if asset:
        return asset.business_unit or asset.asset_type or "Technology"
    text = _text_blob(target, metadata.get("industry"), metadata.get("business_unit"))
    if "bank" in text or "finance" in text or "payment" in text:
        return "Financial Services"
    if "health" in text or "hospital" in text or "clinic" in text:
        return "Healthcare"
    if "gov" in text or "ministry" in text:
        return "Government"
    if "edu" in text or "school" in text or "university" in text:
        return "Education"
    if "cloud" in text or "saas" in text or "app" in text:
        return "Technology"
    return "Technology"


def _infer_company_name(target_label: str | None, country: str, index: int = 0) -> str:
    host = _extract_host(target_label)
    if host:
        parts = [part for part in host.split(".") if part and part not in {"www", "api", "cdn", "mail"}]
        if parts:
            return parts[0].replace("-", " ").replace("_", " ").title()
    options = SAMPLE_COMPANIES_BY_COUNTRY.get(country) or [f"{country} Critical Infrastructure", f"{country} Financial Services", f"{country} Cloud Tenant"]
    return options[index % len(options)]


def _build_flow(
    *,
    flow_id: str,
    source_country: str,
    target_country: str,
    attack_type: str,
    severity: str,
    timestamp: datetime,
    title: str,
    industry: str | None,
    malware_type: str | None,
    ti_source: str | None,
    references: list[str] | None,
    target_label: str | None,
    company_name: str | None = None,
) -> dict:
    return {
        "id": flow_id,
        "source_country": source_country,
        "target_country": target_country,
        "source_region": COUNTRY_REGIONS.get(source_country),
        "target_region": COUNTRY_REGIONS.get(target_country),
        "attack_type": attack_type,
        "severity": severity,
        "timestamp": _isoformat(timestamp),
        "title": title,
        "industry": industry,
        "malware_type": malware_type,
        "ti_source": ti_source,
        "references": references or [],
        "target_label": target_label,
        "company_name": company_name or _infer_company_name(target_label, target_country),
    }


def build_attack_map_data(
    *,
    findings: list[Finding],
    scans: list[Scan],
    assets: list[Asset],
    monitoring_events: list[MonitoringEvent],
    incidents: list[SecurityIncident],
    misp_events: list[dict],
) -> dict:
    scan_map = {str(scan.id): scan for scan in scans}
    asset_map = {str(asset.id): asset for asset in assets}
    flows: list[dict] = []
    now = datetime.now(timezone.utc)

    for finding in findings:
        scan = scan_map.get(str(finding.scan_id))
        asset = asset_map.get(str(finding.asset_id)) if finding.asset_id else None
        target_label = scan.target if scan else asset.url if asset and asset.url else asset.hostname if asset else None
        metadata = finding.finding_metadata or {}
        attack_type = _infer_attack_type(finding.title, finding.evidence, metadata.get("risk"), metadata.get("attack"))
        source_country = SOURCE_COUNTRY_BY_ATTACK.get(attack_type, "United States")
        target_country = (
            _resolve_country_from_host(_extract_host(target_label or (asset.hostname if asset else None)))
            or infer_country(target_label or asset.hostname if asset else None, fallback=DEFAULT_PRIVATE_NETWORK_COUNTRY if finding.source in {"openvas", "network-db"} else "United States")
        )
        flows.append(
            _build_flow(
                flow_id=f"finding-{finding.id}",
                source_country=source_country,
                target_country=target_country,
                attack_type=attack_type,
                severity=(finding.severity or "medium").lower(),
                timestamp=_parse_timestamp(finding.detected_at or finding.last_seen),
                title=finding.title,
                industry=_infer_industry(asset, target_label, metadata),
                malware_type=_infer_malware_type(finding.title, finding.evidence, metadata.get("reference")),
                ti_source="Enriched Findings",
                references=[ref for ref in build_threat_feed([finding], scan_map)[0]["references"][:3]],
                target_label=target_label,
            )
        )

    for event in monitoring_events:
        payload = event.payload or {}
        attack_type = _infer_attack_type(event.event_type, payload.get("summary"), payload.get("attack"), payload.get("signature"))
        source_country = infer_country(payload.get("source_country") or payload.get("origin") or payload.get("src_ip"), fallback=SOURCE_COUNTRY_BY_ATTACK.get(attack_type, "United Kingdom"))
        target_country = infer_country(event.target, fallback="United States")
        flows.append(
            _build_flow(
                flow_id=f"monitor-{event.id}",
                source_country=source_country,
                target_country=target_country,
                attack_type=attack_type,
                severity=(event.severity or "medium").lower(),
                timestamp=_parse_timestamp(event.created_at),
                title=payload.get("summary") or event.event_type.replace("_", " ").title(),
                industry=_infer_industry(None, event.target, payload),
                malware_type=_infer_malware_type(payload.get("summary"), payload.get("signature")),
                ti_source=event.source,
                references=payload.get("references") or [],
                target_label=event.target,
            )
        )

    for incident in incidents:
        metadata = incident.metadata_json or {}
        attack_type = _infer_attack_type(incident.title, incident.summary, metadata.get("attack_type"))
        source_country = infer_country(metadata.get("source_country") or incident.source, fallback=SOURCE_COUNTRY_BY_ATTACK.get(attack_type, "Germany"))
        target_country = infer_country(incident.target, fallback="United States")
        flows.append(
            _build_flow(
                flow_id=f"incident-{incident.id}",
                source_country=source_country,
                target_country=target_country,
                attack_type=attack_type,
                severity=(incident.severity or "high").lower(),
                timestamp=_parse_timestamp(incident.created_at),
                title=incident.title,
                industry=_infer_industry(None, incident.target, metadata),
                malware_type=_infer_malware_type(incident.summary, metadata.get("malware")),
                ti_source=incident.source,
                references=metadata.get("references") or [],
                target_label=incident.target,
            )
        )

    for index, event in enumerate(misp_events):
        attack_type = _infer_attack_type(event.get("name"), event.get("description"), event.get("adversary"), " ".join(event.get("tags") or []))
        source_country = infer_country(event.get("author_name") or event.get("adversary"), fallback=SOURCE_COUNTRY_BY_ATTACK.get(attack_type, "Singapore"))
        target_country = infer_country(event.get("description") or event.get("name"), fallback="United States")
        flows.append(
            _build_flow(
                flow_id=f"misp-{event.get('id') or index}",
                source_country=source_country,
                target_country=target_country,
                attack_type=attack_type,
                severity=(event.get("threat_level") or "medium").lower(),
                timestamp=_parse_timestamp(event.get("modified") or event.get("created")),
                title=event.get("name") or "Threat event",
                industry=_infer_industry(None, event.get("description"), {"industry": event.get("description")}),
                malware_type=_infer_malware_type(event.get("name"), event.get("description"), " ".join(event.get("tags") or [])),
                ti_source="MISP",
                references=[event.get("url")] + list(event.get("references") or []),
                target_label=event.get("name"),
            )
        )

    urlhaus_status, urlhaus_rows = fetch_urlhaus_recent()
    if urlhaus_status == "connected":
        for index, row in enumerate(urlhaus_rows):
            attack_type = "Malware Delivery"
            raw_url = row.get("url") or ""
            host = _extract_host(raw_url)
            source_country = _resolve_country_from_host(host) or infer_country(raw_url, fallback="United States")
            target_country = infer_country(
                " ".join(filter(None, [row.get("tags"), raw_url])),
                fallback=GLOBAL_TARGET_COUNTRIES[index % len(GLOBAL_TARGET_COUNTRIES)],
            )
            title = row.get("tags") if row.get("tags") and row.get("tags") != "None" else (row.get("threat") or "Malware delivery event")
            flows.append(
                _build_flow(
                    flow_id=f"urlhaus-{row.get('id') or index}",
                    source_country=source_country,
                    target_country=target_country,
                    attack_type=attack_type,
                    severity="high",
                    timestamp=_parse_timestamp(row.get("dateadded") or row.get("last_online")),
                    title=title,
                    industry=_infer_industry(None, raw_url, {"industry": row.get("tags")}),
                    malware_type=_infer_malware_type(row.get("tags"), row.get("threat"), raw_url) or "Malware",
                    ti_source="URLhaus",
                    references=[row.get("urlhaus_link")] if row.get("urlhaus_link") else [],
                    target_label=raw_url,
                    company_name=_infer_company_name(raw_url, target_country, index),
                )
            )

    flows.sort(key=lambda item: item["timestamp"], reverse=True)

    def top_countries(hours: int) -> list[dict]:
        threshold = now - timedelta(hours=hours)
        counter = Counter(
            flow["target_country"] for flow in flows if _parse_timestamp(flow["timestamp"]) >= threshold
        )
        return [{"country": country, "attacks": count} for country, count in counter.most_common(12)]

    industry_counter = Counter(flow["industry"] for flow in flows if flow.get("industry"))
    malware_counter = Counter(flow["malware_type"] for flow in flows if flow.get("malware_type"))

    grouped_by_country: dict[str, list[dict]] = defaultdict(list)
    for flow in flows:
        grouped_by_country[flow["target_country"]].append(flow)
        if flow["source_country"] != flow["target_country"]:
            grouped_by_country.setdefault(flow["source_country"], [])

    countries: dict[str, dict] = {}
    for country, country_flows in grouped_by_country.items():
        incoming = [flow for flow in country_flows if flow["target_country"] == country]
        outgoing = [flow for flow in flows if flow["source_country"] == country]
        countries[country] = {
            "country": country,
            "attack_count": len(incoming) + len(outgoing),
            "source_count": len(outgoing),
            "target_count": len(incoming),
            "top_attack_types": [{attack_type: count} for attack_type, count in Counter(flow["attack_type"] for flow in incoming + outgoing).most_common(5)],
            "top_sources": [{source_country: count} for source_country, count in Counter(flow["source_country"] for flow in incoming).most_common(5)],
            "top_industries": [{industry: count} for industry, count in Counter(flow["industry"] for flow in incoming if flow.get("industry")).most_common(5)],
            "top_malware": [{malware: count} for malware, count in Counter(flow["malware_type"] for flow in incoming if flow.get("malware_type")).most_common(5)],
            "latest_flows": incoming[:12],
        }

    return {
        "generated_at": _isoformat(now),
        "daily_attack_count": sum(1 for flow in flows if _parse_timestamp(flow["timestamp"]) >= now.replace(hour=0, minute=0, second=0, microsecond=0)),
        "active_flow_count": len(flows),
        "flows": flows[:500],
        "most_attacked_1h": top_countries(1),
        "most_attacked_12h": top_countries(12),
        "most_attacked_24h": top_countries(24),
        "most_targeted_industries": [{"industry": industry, "attacks": count} for industry, count in industry_counter.most_common(8)],
        "top_malware_types": [{"malware_type": malware, "attacks": count} for malware, count in malware_counter.most_common(8)],
        "countries": countries,
    }
