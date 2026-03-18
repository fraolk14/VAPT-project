import os
from typing import Any

import requests


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class OpenVASClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("OPENVAS_API_URL", "http://openvas:9392")
        self.username = os.getenv("OPENVAS_USERNAME", "admin")
        self.password = os.getenv("OPENVAS_PASSWORD", "admin")

    def launch_scan(self, target: str, profile: str = "Full and fast") -> dict[str, Any]:
        return {
            "engine": "openvas",
            "target": target,
            "profile": profile,
            "remote_task_id": f"openvas-{target}",
            "status": "queued",
        }

    def normalize_results(self, raw_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for item in raw_results:
            normalized.append(
                {
                    "title": item.get("name", "OpenVAS finding"),
                    "category": "network",
                    "source": "openvas",
                    "port": int(item.get("port", 0)),
                    "protocol": item.get("protocol", "tcp"),
                    "service": item.get("service"),
                    "state": item.get("state", "open"),
                    "cve_id": item.get("cve"),
                    "cvss_score": item.get("cvss"),
                    "severity": _severity_from_score(item.get("cvss")),
                    "evidence": item.get("evidence"),
                    "remediation": item.get("solution"),
                    "compliance_map": ["OWASP ASVS V1", "NIST RA-5"],
                    "metadata": {"host": item.get("host"), "oid": item.get("oid")},
                }
            )
        return normalized


class ZAPClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("ZAP_API_URL", "http://zap:8080")
        self.api_key = os.getenv("ZAP_API_KEY", "zap")

    def launch_scan(self, target: str, mode: str = "active") -> dict[str, Any]:
        return {
            "engine": "zap",
            "target": target,
            "mode": mode,
            "status": "queued",
            "remote_task_id": f"zap-{target}",
        }

    def normalize_results(self, raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for alert in raw_alerts:
            score = float(alert.get("risk_score", 0.0))
            normalized.append(
                {
                    "title": alert.get("alert", "ZAP alert"),
                    "category": "web",
                    "source": "zap",
                    "port": int(alert.get("port", 80)),
                    "protocol": alert.get("protocol", "https"),
                    "service": "http",
                    "state": "open",
                    "cve_id": alert.get("cveid"),
                    "cvss_score": score,
                    "severity": _severity_from_score(score),
                    "evidence": alert.get("evidence"),
                    "remediation": alert.get("solution"),
                    "compliance_map": ["OWASP Top 10", "CWE"],
                    "metadata": {"url": alert.get("url"), "param": alert.get("param")},
                }
            )
        return normalized


class MobSFClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("MOBSF_API_URL", "http://mobsf:8000")
        self.api_key = os.getenv("MOBSF_API_KEY", "mobsf")

    def launch_scan(self, file_name: str) -> dict[str, Any]:
        return {
            "engine": "mobsf",
            "target": file_name,
            "status": "queued",
            "remote_task_id": f"mobsf-{file_name}",
        }

    def normalize_results(self, raw_issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for issue in raw_issues:
            score = float(issue.get("cvss", 5.0))
            normalized.append(
                {
                    "title": issue.get("title", "Mobile finding"),
                    "category": "mobile",
                    "source": "mobsf",
                    "port": 0,
                    "protocol": "file",
                    "service": "mobile-binary",
                    "state": "open",
                    "cve_id": issue.get("cve"),
                    "cvss_score": score,
                    "severity": _severity_from_score(score),
                    "evidence": issue.get("description"),
                    "remediation": issue.get("recommendation"),
                    "compliance_map": ["MASVS"],
                    "metadata": {"file": issue.get("file"), "rule": issue.get("rule")},
                }
            )
        return normalized


def integration_health() -> dict[str, Any]:
    services = {
        "openvas": os.getenv("OPENVAS_API_URL", "http://openvas:9392"),
        "zap": os.getenv("ZAP_API_URL", "http://zap:8080"),
        "mobsf": os.getenv("MOBSF_API_URL", "http://mobsf:8000"),
    }
    health = {}
    for name, base_url in services.items():
        try:
            response = requests.get(base_url, timeout=2)
            health[name] = {"healthy": response.status_code < 500, "url": base_url}
        except requests.RequestException:
            health[name] = {"healthy": False, "url": base_url}
    return health
