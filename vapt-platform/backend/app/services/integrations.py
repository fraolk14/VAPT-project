import os
from contextlib import contextmanager
from typing import Any
from uuid import uuid4
from xml.etree import ElementTree as ET

import requests
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP


DEFAULT_OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
DEFAULT_OPENVAS_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
DEFAULT_OPENVAS_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
DEFAULT_OPENVAS_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"


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


def _xml_transform(response: Any) -> ET.Element:
    payload = getattr(response, "data", response)
    if isinstance(payload, str):
        payload = payload.encode()
    return ET.fromstring(payload)


def _safe_float(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _text(element: ET.Element | None, path: str, default: str | None = None) -> str | None:
    if element is None:
        return default
    found = element.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _split_port(port_value: str | None) -> tuple[int, str]:
    if not port_value:
        return 0, "tcp"
    value = port_value.split()[0]
    if "/" in value:
        port_text, protocol = value.split("/", 1)
        try:
            return int(port_text), protocol
        except ValueError:
            return 0, protocol
    try:
        return int(value), "tcp"
    except ValueError:
        return 0, "tcp"


class OpenVASClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("OPENVAS_API_URL", "http://host.docker.internal:9392")
        self.username = os.getenv("OPENVAS_USERNAME", "admin")
        self.password = os.getenv("OPENVAS_PASSWORD", "admin")
        self.socket_path = os.getenv("OPENVAS_SOCKET_PATH", "/run/gvmd/gvmd.sock")
        self.scanner_id = os.getenv("OPENVAS_SCANNER_ID", DEFAULT_OPENVAS_SCANNER_ID)
        self.scan_config_id = os.getenv(
            "OPENVAS_SCAN_CONFIG_ID", DEFAULT_OPENVAS_SCAN_CONFIG_ID
        )
        self.port_list_id = os.getenv("OPENVAS_PORT_LIST_ID", DEFAULT_OPENVAS_PORT_LIST_ID)
        self.report_format_id = os.getenv(
            "OPENVAS_REPORT_FORMAT_ID", DEFAULT_OPENVAS_REPORT_FORMAT_ID
        )

    @contextmanager
    def _gmp(self):
        connection = UnixSocketConnection(path=self.socket_path)
        with GMP(connection, transform=_xml_transform) as gmp:
            gmp.authenticate(self.username, self.password)
            yield gmp

    def _resolve_scan_config_id(self, gmp: GMP, profile: str) -> str:
        response = gmp.get_scan_configs()
        configs = response.findall(".//config")
        if not configs:
            raise RuntimeError(
                "Greenbone scan configurations are not available yet. Wait for the feed/config sync to complete in Greenbone, then retry."
            )

        for config in configs:
            if config.attrib.get("id") == self.scan_config_id:
                return self.scan_config_id

        for config in configs:
            if (_text(config, "./name", "") or "").lower() == profile.lower():
                config_id = config.attrib.get("id")
                if config_id:
                    return config_id

        available = ", ".join(
            filter(None, [(_text(config, "./name", "") or "") for config in configs])
        )
        raise RuntimeError(
            f"Requested Greenbone scan profile '{profile}' is not available. Available profiles: {available or 'none'}."
        )

    def launch_scan(self, target: str, profile: str = "Full and fast") -> dict[str, Any]:
        task_name = f"codex-{target}-{uuid4().hex[:8]}"
        target_name = f"codex-target-{target}-{uuid4().hex[:8]}"

        try:
            with self._gmp() as gmp:
                config_id = self._resolve_scan_config_id(gmp, profile)
                target_response = gmp.create_target(
                    name=target_name,
                    hosts=[target],
                    port_list_id=self.port_list_id,
                )
                target_id = target_response.get("id")

                task_response = gmp.create_task(
                    name=task_name,
                    config_id=config_id,
                    scanner_id=self.scanner_id,
                    target_id=target_id,
                    comment=f"Created by VAPT platform with profile {profile}",
                )
                task_id = task_response.get("id")
                start_response = gmp.start_task(task_id)
        except GvmError as exc:
            raise RuntimeError(f"Greenbone task creation failed: {exc}") from exc

        report_id = _text(start_response, ".//report_id")
        return {
            "engine": "openvas",
            "target": target,
            "profile": profile,
            "target_name": target_name,
            "remote_target_id": target_id,
            "remote_task_id": task_id,
            "remote_report_id": report_id,
            "remote_scan_config_id": config_id,
            "status": "requested",
        }

    def get_task_status(self, task_id: str) -> dict[str, Any]:
        with self._gmp() as gmp:
            response = gmp.get_task(task_id=task_id)

        task = response.find(".//task")
        status_text = (_text(task, "./status", "Queued") or "Queued").strip()
        progress = (_text(task, "./progress", "0") or "0").strip()
        report_id = None

        report = task.find(".//last_report/report") if task is not None else None
        if report is not None:
            report_id = report.attrib.get("id")
        if not report_id:
            report_id = _text(task, ".//report_id")

        mapped_status = {
            "new": "queued",
            "requested": "queued",
            "queued": "queued",
            "running": "running",
            "done": "completed",
            "stopped": "failed",
            "delete requested": "failed",
            "internal error": "failed",
        }.get(status_text.lower(), "running")

        return {
            "status": mapped_status,
            "status_text": status_text,
            "progress": progress,
            "remote_report_id": report_id,
        }

    def get_report_results(self, report_id: str) -> list[dict[str, Any]]:
        with self._gmp() as gmp:
            response = gmp.get_report(
                report_id=report_id,
                report_format_id=self.report_format_id,
                details=True,
                ignore_pagination=True,
            )

        results: list[dict[str, Any]] = []
        for result in response.findall(".//result"):
            severity_score = _safe_float(_text(result, "./severity"))
            port, protocol = _split_port(_text(result, "./port"))
            refs = result.findall(".//nvt/refs/ref")
            cve_id = next((ref.attrib.get("id") for ref in refs if ref.attrib.get("type") == "cve"), None)
            results.append(
                {
                    "title": _text(result, "./name")
                    or _text(result, ".//nvt/name")
                    or "OpenVAS finding",
                    "category": "network",
                    "source": "openvas",
                    "port": port,
                    "protocol": protocol,
                    "service": _text(result, "./service") or _text(result, "./port"),
                    "state": "open",
                    "cve_id": cve_id,
                    "cvss_score": severity_score,
                    "severity": _severity_from_score(severity_score),
                    "evidence": _text(result, "./description"),
                    "remediation": _text(result, ".//nvt/solution"),
                    "compliance_map": ["OWASP ASVS V1", "NIST RA-5"],
                    "metadata": {
                        "host": _text(result, "./host"),
                        "threat": _text(result, "./threat"),
                        "qod": _text(result, "./qod/value"),
                        "report_id": report_id,
                    },
                }
            )
        return results

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
        "openvas": os.getenv("OPENVAS_API_URL", "http://host.docker.internal:9392"),
        "zap": os.getenv("ZAP_API_URL", "http://zap:8080"),
        "mobsf": os.getenv("MOBSF_API_URL", "http://mobsf:8000"),
    }
    health = {}
    for name, base_url in services.items():
        try:
            response = requests.get(base_url, timeout=2, verify=False)
            health[name] = {"healthy": response.status_code < 500, "url": base_url}
        except requests.RequestException:
            health[name] = {"healthy": False, "url": base_url}
    return health
