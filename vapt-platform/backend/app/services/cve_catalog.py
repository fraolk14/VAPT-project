from __future__ import annotations

import gzip
import io
import json
import os
import re
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc
from typing import Any

import requests
from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.vulnerability import Vulnerability
from app.models.finding import Finding
from app.services.severity import severity_from_score as _severity

NVD_FEED_BASE_URL = os.getenv("NVD_FEED_BASE_URL", "https://nvd.nist.gov/feeds/json/cve/2.0")
CVE_SYNC_START_YEAR = int(os.getenv("CVE_SYNC_START_YEAR", "2002"))
CVE_SYNC_TIMEOUT = int(os.getenv("CVE_SYNC_TIMEOUT", "120"))
CVE_MATCH_LIMIT = int(os.getenv("CVE_MATCH_LIMIT", "5"))
TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9._+-]{2,}")
GENERIC_SERVICE_VALUES = {"http", "https", "tcp", "ftp", "file", "web", "network", "mobile-binary"}


def _current_year() -> int:
    return datetime.now(UTC).year


def sync_years() -> list[int]:
    return list(range(CVE_SYNC_START_YEAR, _current_year() + 1))


def _feed_url(year: int) -> str:
    return f"{NVD_FEED_BASE_URL}/nvdcve-2.0-{year}.json.gz"


def _request_feed(url: str) -> dict[str, Any]:
    response = requests.get(url, timeout=CVE_SYNC_TIMEOUT)
    response.raise_for_status()
    with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise RuntimeError("Downloaded CVE feed did not contain a JSON object.")
    return payload


def _pick_english_description(descriptions: list[dict[str, Any]] | None) -> str:
    for item in descriptions or []:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    for item in descriptions or []:
        if item.get("value"):
            return str(item["value"]).strip()
    return ""


def _extract_cvss(metrics: dict[str, Any] | None) -> tuple[float, str | None]:
    metrics = metrics or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData") or {}
        score = cvss_data.get("baseScore")
        vector = cvss_data.get("vectorString")
        if isinstance(score, (int, float)):
            return float(score), vector
    return 0.0, None



def _extract_weaknesses(weaknesses: list[dict[str, Any]] | None) -> list[str]:
    results: list[str] = []
    for weakness in weaknesses or []:
        for description in weakness.get("description") or []:
            value = description.get("value")
            if value:
                results.append(str(value))
    return list(dict.fromkeys(results))[:8]


def _extract_mitre_attack_tags(description: str, weaknesses: list[str]) -> list[str]:
    tags = []
    desc = description.lower()
    mapping = {
        "sql injection": "T1190",
        "cross-site scripting": "T1059.007",
        "path traversal": "T1006",
        "remote code execution": "T1203",
        "deserialization": "T1190",
        "credentials": "T1552",
    }
    for marker, attack in mapping.items():
        if marker in desc:
            tags.append(attack)
    for weakness in weaknesses:
        if "CWE-79" in weakness:
            tags.append("T1059.007")
        if "CWE-89" in weakness:
            tags.append("T1190")
    return list(dict.fromkeys(tags))


def _extract_reference(cve: dict[str, Any]) -> str | None:
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if url:
            return str(url)
    return None


def _title_from_description(cve_id: str, description: str) -> str:
    if not description:
        return cve_id
    sentence = description.split(".")[0].strip()
    if len(sentence) < 18:
        return description[:180]
    return sentence[:180]


def _row_from_nvd_record(record: dict[str, Any]) -> dict[str, Any] | None:
    cve = record.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None
    description = _pick_english_description(cve.get("descriptions"))
    cvss_score, vector = _extract_cvss(cve.get("metrics"))
    weaknesses = _extract_weaknesses(cve.get("weaknesses"))
    return {
        "cve_id": str(cve_id),
        "title": _title_from_description(str(cve_id), description),
        "description": description or str(cve_id),
        "cvss_score": cvss_score,
        "severity": _severity(cvss_score),
        "cvss_vector": vector,
        "exploitability": 1.0 if cve.get("cisaExploitAdd") else 0.0,
        "compliance_tags": ["NVD", "CVE", *weaknesses[:4]],
        "mitre_attack": _extract_mitre_attack_tags(description, weaknesses),
        "remediation": "Review vendor advisories and patch guidance referenced for this CVE.",
        "reference": _extract_reference(cve),
    }


def sync_cve_catalog(db: Session, years: list[int] | None = None) -> dict[str, Any]:
    years = years or sync_years()
    imported = 0
    feeds_processed = 0
    rows_buffer: list[dict[str, Any]] = []
    batch_size = 500

    for year in years:
        payload = _request_feed(_feed_url(year))
        feeds_processed += 1
        for record in payload.get("vulnerabilities") or []:
            row = _row_from_nvd_record(record)
            if not row:
                continue
            rows_buffer.append(row)
            if len(rows_buffer) >= batch_size:
                _upsert_rows(db, rows_buffer)
                imported += len(rows_buffer)
                rows_buffer = []

    if rows_buffer:
        _upsert_rows(db, rows_buffer)
        imported += len(rows_buffer)

    total = db.scalar(select(Vulnerability).count()) if False else db.query(Vulnerability).count()
    return {
        "feeds_processed": feeds_processed,
        "rows_imported": imported,
        "catalog_size": total,
        "years": years,
    }


def _upsert_rows(db: Session, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    stmt = insert(Vulnerability).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=[Vulnerability.cve_id],
        set_={
            "title": stmt.excluded.title,
            "description": stmt.excluded.description,
            "cvss_score": stmt.excluded.cvss_score,
            "severity": stmt.excluded.severity,
            "cvss_vector": stmt.excluded.cvss_vector,
            "exploitability": stmt.excluded.exploitability,
            "compliance_tags": stmt.excluded.compliance_tags,
            "mitre_attack": stmt.excluded.mitre_attack,
            "remediation": stmt.excluded.remediation,
            "reference": stmt.excluded.reference,
        },
    )
    db.execute(stmt)
    db.commit()


def _tokens_from_item(item: dict[str, Any]) -> list[str]:
    metadata = item.get("metadata") or {}
    blob = " ".join(
        part
        for part in [
            item.get("title"),
            item.get("evidence"),
            item.get("remediation"),
            item.get("service"),
            metadata.get("banner"),
            metadata.get("page_title"),
        ]
        if part
    ).lower()
    blacklist = {
        "missing", "service", "port", "http", "https", "response", "detected", "exposed",
        "protection", "header", "headers", "content", "security", "tcp", "host", "server",
    }
    tokens = [token for token in TOKEN_PATTERN.findall(blob) if len(token) >= 4 and token not in blacklist]
    return list(dict.fromkeys(tokens))[:10]


def _similarity_score(item: dict[str, Any], vulnerability: Vulnerability) -> float:
    text = " ".join(
        part.lower()
        for part in [
            item.get("title") or "",
            item.get("evidence") or "",
            item.get("service") or "",
            ((item.get("metadata") or {}).get("banner") or ""),
        ]
    )
    vuln_text = f"{vulnerability.title} {vulnerability.description}".lower()
    item_tokens = set(_tokens_from_item(item))
    vuln_tokens = set(TOKEN_PATTERN.findall(vuln_text))
    overlap = len(item_tokens & vuln_tokens)
    if overlap == 0:
        return 0.0
    score = overlap / max(4, len(item_tokens))
    service = (item.get("service") or "").lower().strip()
    if service and service not in GENERIC_SERVICE_VALUES:
        if service in vuln_text:
            score += 0.35
        else:
            score -= 0.2
    banner = (((item.get("metadata") or {}).get("banner") or "")).lower()
    if banner and any(token in vuln_text for token in TOKEN_PATTERN.findall(banner)[:4]):
        score += 0.2
    if vulnerability.cve_id.lower() in text:
        score += 0.6
    if vulnerability.title.lower()[:48] in text:
        score += 0.2
    return score


def match_local_cve_catalog(db: Session, item: dict[str, Any]) -> list[dict[str, Any]]:
    tokens = _tokens_from_item(item)
    if not tokens:
        return []
    clauses = []
    for token in tokens[:5]:
        like = f"%{token}%"
        clauses.append(Vulnerability.title.ilike(like))
        clauses.append(Vulnerability.description.ilike(like))
    candidates = db.query(Vulnerability).filter(or_(*clauses)).limit(80).all()
    ranked: list[tuple[float, Vulnerability]] = []
    for candidate in candidates:
        score = _similarity_score(item, candidate)
        if score >= 0.55:
            ranked.append((score, candidate))
    ranked.sort(key=lambda entry: (entry[0], entry[1].cvss_score or 0.0), reverse=True)
    results: list[dict[str, Any]] = []
    for score, candidate in ranked[:CVE_MATCH_LIMIT]:
        results.append(
            {
                "cve_id": candidate.cve_id,
                "score": round(score, 3),
                "title": candidate.title,
                "description": candidate.description,
                "cvss_score": candidate.cvss_score,
                "severity": candidate.severity,
                "reference": candidate.reference,
                "mitre_attack": candidate.mitre_attack or [],
            }
        )
    return results


def _finding_to_correlation_item(finding: Finding) -> dict[str, Any]:
    return {
        "title": finding.title,
        "category": finding.category,
        "source": finding.source,
        "port": finding.port,
        "protocol": finding.protocol,
        "service": finding.service,
        "state": finding.state,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "compliance_map": finding.compliance_map or [],
        "metadata": finding.finding_metadata or {},
    }


def reprocess_findings_against_catalog(db: Session, *, scan_id: str | None = None, batch_size: int = 250) -> dict[str, Any]:
    from app.services.vulnerability_correlation import correlate_finding

    query = db.query(Finding).order_by(Finding.detected_at.asc())
    if scan_id:
        query = query.filter(Finding.scan_id == scan_id)

    processed = 0
    updated = 0
    findings = query.all()
    for finding in findings:
        processed += 1
        correlated = correlate_finding(_finding_to_correlation_item(finding), db=db)
        changed = False
        for attr, key in [
            ("cve_id", "cve_id"),
            ("cvss_score", "cvss_score"),
            ("severity", "severity"),
            ("confidence", "confidence"),
            ("evidence", "evidence"),
            ("remediation", "remediation"),
        ]:
            new_value = correlated.get(key)
            if getattr(finding, attr) != new_value:
                setattr(finding, attr, new_value)
                changed = True
        if finding.compliance_map != correlated.get("compliance_map", []):
            finding.compliance_map = correlated.get("compliance_map", [])
            changed = True
        if finding.finding_metadata != correlated.get("metadata", {}):
            finding.finding_metadata = correlated.get("metadata", {})
            changed = True
        if changed:
            updated += 1
        if processed % batch_size == 0:
            db.commit()

    db.commit()
    return {
        "processed": processed,
        "updated": updated,
        "scan_id": scan_id,
    }
