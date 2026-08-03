import os
import re
from functools import lru_cache

import requests

from app.services.severity import severity_from_score

NVD_SEARCH_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_SEARCH_TIMEOUT = float(os.getenv("NVD_SEARCH_TIMEOUT", "8"))

DEFAULT_CVE_FALLBACKS = {
    "http": ("CVE-2023-44487", 7.5, "high"),
    "https": ("CVE-2023-44487", 7.5, "high"),
    "nginx": ("CVE-2023-44487", 7.5, "high"),
    "postgres": ("CVE-2022-1552", 6.5, "medium"),
    "postgresql": ("CVE-2022-1552", 6.5, "medium"),
    "apache": ("CVE-2023-25690", 7.2, "high"),
    "openssl": ("CVE-2023-0286", 7.5, "high"),
    "redis": ("CVE-2022-0543", 6.5, "medium"),
    "elasticsearch": ("CVE-2015-1427", 6.8, "medium"),
    "log4j": ("CVE-2021-44228", 10.0, "critical"),
}


def _normalize_service_name(service_name: str) -> str:
    if not service_name:
        return ""
    return re.sub(r"[^a-z0-9]+", " ", str(service_name).lower()).strip()


@lru_cache(maxsize=256)
def _search_nvd_for_service(service_name: str) -> tuple[str | None, float | None, str | None]:
    normalized = _normalize_service_name(service_name)
    if not normalized:
        return None, None, None

    search_terms = [normalized]
    if normalized in {"postgres", "postgresql"}:
        search_terms.append("postgresql database")
    if normalized in {"http", "https"}:
        search_terms.append("http server")
    if normalized == "nginx":
        search_terms.append("nginx http server")
    if normalized == "apache":
        search_terms.append("apache http server")

    for term in dict.fromkeys(search_terms):
        try:
            response = requests.get(
                NVD_SEARCH_URL,
                params={"keywordSearch": term, "resultsPerPage": 5, "noRejected": "true"},
                timeout=NVD_SEARCH_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue
        for vulnerability in payload.get("vulnerabilities") or []:
            cve = vulnerability.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            metrics = cve.get("metrics") or {}
            score = None
            for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(metric_key) or []
                if not entries:
                    continue
                base_score = (entries[0].get("cvssData") or {}).get("baseScore")
                if isinstance(base_score, (int, float)):
                    score = float(base_score)
                    break
            if score is None:
                continue
            return str(cve_id), score, severity_from_score(score)

    return None, None, None


def lookup_cve_for_service(service_name: str):
    """
    Return a live CVE enrichment payload when NVD is reachable and fall back to a
    conservative static list when the network lookup is unavailable.
    """
    normalized = _normalize_service_name(service_name)
    if not normalized:
        return {"cve_id": None, "cvss_score": None, "severity": None}

    cve_id, cvss_score, severity = _search_nvd_for_service(normalized)
    if cve_id:
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
        }

    fallback = DEFAULT_CVE_FALLBACKS.get(normalized)
    if fallback:
        cve_id, cvss_score, severity = fallback
        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
        }

    return {
        "cve_id": None,
        "cvss_score": None,
        "severity": None,
    }
