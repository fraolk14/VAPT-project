import os
import re
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse
from typing import Any
from uuid import uuid4
from xml.etree import ElementTree as ET

import requests
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import GMP
from app.services.severity import severity_from_score as _severity_from_score

DEFAULT_OPENVAS_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
DEFAULT_OPENVAS_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
DEFAULT_OPENVAS_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"
DEFAULT_OPENVAS_REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _severity_from_openvas(score: float | None, threat: str | None, title: str | None = None) -> str:
    if score is not None and score > 0:
        return _severity_from_score(score)

    threat_text = (threat or "").strip().lower()
    if threat_text in {"critical", "alarm"}:
        return "critical"
    if threat_text == "high":
        return "high"
    if threat_text == "medium":
        return "medium"
    if threat_text == "low":
        return "low"

    title_text = (title or "").lower()
    if any(keyword in title_text for keyword in ["remote code", "rce", "sql injection", "auth bypass", "default credentials"]):
        return "critical"
    return "info"


def _severity_from_zap(score: float | None, risk: str | None, title: str | None = None) -> tuple[str, float | None]:
    if score is not None and score > 0:
        return _severity_from_score(score), score

    risk_text = (risk or "").strip().lower()
    title_text = (title or "").lower()
    if risk_text == "high":
        if any(keyword in title_text for keyword in ["sql injection", "command injection", "remote code", "auth bypass", "server side request forgery", "ssrf"]):
            return "critical", 9.4
        return "high", 8.0
    if risk_text == "medium":
        if any(keyword in title_text for keyword in ["cross site scripting", "xss", "csrf", "path traversal", "directory traversal"]):
            return "high", 7.5
        return "medium", 5.6
    if risk_text == "low":
        return "low", 3.1
    return "info", 0.0


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


def _extract_cve_candidates(*values: str | None) -> list[str]:
    matches: list[str] = []
    for value in values:
        if not value:
            continue
        matches.extend(match.upper() for match in CVE_PATTERN.findall(value))
    return sorted(dict.fromkeys(matches))


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
        connection = UnixSocketConnection(path=self.socket_path, timeout=180)
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

    def stop_task(self, task_id: str) -> None:
        try:
            with self._gmp() as gmp:
                stop_task = getattr(gmp, "stop_task", None)
                if callable(stop_task):
                    stop_task(task_id=task_id)
        except GvmError:
            return

    def get_report_results(self, report_id: str, task_id: str | None = None) -> list[dict[str, Any]]:
        with self._gmp() as gmp:
            if task_id:
                response = gmp.get_results(task_id=task_id, details=True)
            else:
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
            cve_refs = [
                ref.attrib.get("id", "").upper()
                for ref in refs
                if ref.attrib.get("type") == "cve" and ref.attrib.get("id")
            ]
            cve_candidates = _extract_cve_candidates(
                _text(result, "./description"),
                _text(result, ".//nvt/tags"),
                _text(result, ".//nvt/summary"),
            )
            cve_values = sorted(dict.fromkeys([*cve_refs, *cve_candidates]))
            cve_id = ", ".join(cve_values) if cve_values else None
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
                    "severity": _severity_from_openvas(
                        severity_score,
                        _text(result, "./threat"),
                        _text(result, "./name") or _text(result, ".//nvt/name"),
                    ),
                    "evidence": _text(result, "./description"),
                    "remediation": _text(result, ".//nvt/solution"),
                    "compliance_map": ["OWASP ASVS V1", "NIST RA-5"],
                    "metadata": {
                        "host": _text(result, "./host"),
                        "threat": _text(result, "./threat"),
                        "qod": _text(result, "./qod/value"),
                        "report_id": report_id,
                        "cve_refs": cve_values,
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

    def _request(self, component: str, category: str, name: str, **params: Any) -> dict[str, Any]:
        try:
            response = requests.get(
                f"{self.base_url}/JSON/{component}/{category}/{name}/",
                params={"apikey": self.api_key, **params},
                timeout=15,
                verify=False,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"Unable to reach ZAP at {self.base_url}: {exc}") from exc
        except ValueError as exc:
            raise RuntimeError("ZAP returned a non-JSON response.") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Unexpected ZAP API response")
        return payload

    def normalize_target(self, target: str) -> str:
        normalized = target.strip()
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError("Web scans require a valid absolute http:// or https:// URL.")
        return normalized

    def launch_scan(self, target: str, mode: str = "spider-active") -> dict[str, Any]:
        normalized_target = self.normalize_target(target)
        payload = self._request("spider", "action", "scan", url=normalized_target, maxChildren=0, recurse="true")
        spider_scan_id = payload.get("scan")
        if not spider_scan_id:
            raise RuntimeError("ZAP did not return a spider scan id.")
        return {
            "engine": "zap",
            "target": normalized_target,
            "mode": mode,
            "status": "queued",
            "phase": "spider",
            "spider_scan_id": str(spider_scan_id),
            "remote_task_id": str(spider_scan_id),
        }

    def get_spider_status(self, spider_scan_id: str) -> dict[str, Any]:
        payload = self._request("spider", "view", "status", scanId=spider_scan_id)
        progress = int(payload.get("status", "0"))
        return {"status": "completed" if progress >= 100 else "running", "progress": progress}

    def launch_active_scan(self, target: str) -> dict[str, Any]:
        normalized_target = self.normalize_target(target)
        target_no_slash = normalized_target.rstrip("/")
        target_slash = f"{target_no_slash}/"

        active_scan_id = None
        for candidate_url in [normalized_target, target_no_slash, target_slash]:
            try:
                payload = self._request("ascan", "action", "scan", url=candidate_url, recurse="true")
                if payload and payload.get("scan") is not None:
                    active_scan_id = payload.get("scan")
                    break
            except Exception:
                try:
                    payload = self._request("ascan", "action", "scan", url=candidate_url)
                    if payload and payload.get("scan") is not None:
                        active_scan_id = payload.get("scan")
                        break
                except Exception:
                    continue

        if active_scan_id is None:
            return {"active_scan_id": "0", "phase": "active"}

        return {"active_scan_id": str(active_scan_id), "phase": "active"}

    def get_active_scan_status(self, active_scan_id: str) -> dict[str, Any]:
        payload = self._request("ascan", "view", "status", scanId=active_scan_id)
        progress = int(payload.get("status", "0"))
        return {"status": "completed" if progress >= 100 else "running", "progress": progress}

    def get_alerts(self, target: str) -> list[dict[str, Any]]:
        normalized_target = self.normalize_target(target)
        target_no_slash = normalized_target.rstrip("/")
        target_slash = f"{target_no_slash}/"

        for b_url in [normalized_target, target_no_slash, target_slash, None]:
            alerts: list[dict[str, Any]] = []
            start = 0
            count = 500
            try:
                while True:
                    params: dict[str, Any] = {"start": start, "count": count}
                    if b_url:
                        params["baseurl"] = b_url
                    payload = self._request("core", "view", "alerts", **params)
                    batch = payload.get("alerts", [])
                    if not isinstance(batch, list) or not batch:
                        break
                    alerts.extend(batch)
                    if len(batch) < count:
                        break
                    start += count
            except Exception:
                pass

            if alerts:
                return alerts

        return []

    def normalize_results(self, raw_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []
        for alert in raw_alerts:
            score = _safe_float(alert.get("risk_score")) or _safe_float(alert.get("riskcode"))
            severity, normalized_score = _severity_from_zap(score, alert.get("risk"), alert.get("alert"))
            confidence_text = (alert.get("confidence") or "").strip().lower()
            confidence = {
                "false positive": 0.1,
                "low": 0.35,
                "medium": 0.65,
                "high": 0.9,
                "confirmed": 0.98,
            }.get(confidence_text, 0.5)
            parsed_url = urlparse(alert.get("url", ""))
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            protocol = parsed_url.scheme or alert.get("protocol", "https")
            cwe_id = alert.get("cweid")
            cwe_tag = f"CWE-{cwe_id}" if cwe_id not in {None, "", "0"} else None
            cve_candidates = _extract_cve_candidates(
                alert.get("cveid"),
                alert.get("reference"),
                alert.get("otherinfo"),
                alert.get("desc"),
                alert.get("evidence"),
            )
            cve_id = ", ".join(cve_candidates) if cve_candidates else None
            desc = alert.get("description") or alert.get("desc") or ""
            evidence_str = alert.get("evidence") or alert.get("otherinfo") or alert.get("other") or ""
            if desc and evidence_str and desc != evidence_str:
                details_text = f"{desc} | Evidence: {evidence_str}"
            else:
                details_text = desc or evidence_str or alert.get("solution") or "ZAP detected security vulnerability."

            normalized.append(
                {
                    "title": alert.get("alert", "ZAP alert"),
                    "category": "web",
                    "source": "zap",
                    "port": int(port),
                    "protocol": protocol,
                    "service": protocol,
                    "state": "open",
                    "cve_id": cve_id,
                    "cvss_score": normalized_score,
                    "severity": severity,
                    "evidence": details_text,
                    "remediation": alert.get("solution"),
                    "compliance_map": [tag for tag in ["OWASP Top 10", cwe_tag] if tag],
                    "confidence": confidence,
                    "metadata": {
                        "url": alert.get("url"),
                        "param": alert.get("param"),
                        "plugin_id": alert.get("pluginId"),
                        "confidence": alert.get("confidence"),
                        "risk": alert.get("risk"),
                        "attack": alert.get("attack"),
                        "reference": alert.get("reference"),
                        "description": desc,
                        "cwe_id": cwe_id,
                        "cve_refs": cve_candidates,
                    },
                }
            )
        return normalized


class MobSFClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("MOBSF_API_URL", "http://mobsf:8000")
        self.api_key = os.getenv("MOBSF_API_KEY", "mobsf")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self.api_key,
            "X-Mobsf-Api-Key": self.api_key,
        }

    def launch_scan(self, file_name: str, file_path: str | None = None) -> dict[str, Any]:
        return {
            "engine": "mobsf",
            "target": file_name,
            "status": "queued",
            "remote_task_id": f"mobsf-{file_name}",
            "stored_file_path": file_path,
        }

    def upload_binary(self, file_path: str, file_name: str) -> dict[str, Any]:
        path = Path(file_path)
        with path.open("rb") as handle:
            response = requests.post(
                f"{self.base_url}/api/v1/upload",
                headers=self._headers(),
                files={"file": (file_name, handle, "application/octet-stream")},
                timeout=120,
                verify=False,
            )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("MobSF returned an unexpected upload response.")
        return payload

    def request_scan(self, file_hash: str, scan_type: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/api/v1/scan",
            headers=self._headers(),
            data={"hash": file_hash, "scan_type": scan_type},
            timeout=240,
            verify=False,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("MobSF returned an unexpected scan response.")
        return payload

    def request_report(self, file_hash: str) -> dict[str, Any]:
        response = requests.post(
            f"{self.base_url}/api/v1/report_json",
            headers=self._headers(),
            data={"hash": file_hash},
            timeout=180,
            verify=False,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("MobSF returned an unexpected report response.")
        return payload

    def scan_binary(self, file_path: str, file_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        upload_payload = self.upload_binary(file_path, file_name)
        file_hash = upload_payload.get("hash")
        scan_type = upload_payload.get("scan_type") or upload_payload.get("analyzer") or ("ipa" if file_name.lower().endswith(".ipa") else "apk")
        if not file_hash:
            raise RuntimeError("MobSF upload did not return a file hash.")
        scan_payload = self.request_scan(str(file_hash), str(scan_type))
        report_payload = scan_payload if scan_payload.get("hash") else self.request_report(str(file_hash))
        return self.normalize_report(report_payload), {
            "analysis_engine": "mobsf-api",
            "hash": file_hash,
            "scan_type": scan_type,
            "app_name": report_payload.get("app_name") or report_payload.get("appname"),
            "package_name": report_payload.get("package_name") or report_payload.get("package"),
            "version_name": report_payload.get("version_name") or report_payload.get("version"),
            "platform": "ios" if str(scan_type).lower().startswith("ipa") else "android",
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

    def normalize_report(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        package_name = report.get("package_name") or report.get("package")
        bundle_id = report.get("bundle_id")
        common_metadata = {
            "package_name": package_name,
            "bundle_id": bundle_id,
            "app_name": report.get("app_name") or report.get("appname"),
            "version_name": report.get("version_name") or report.get("version"),
        }

        permissions = report.get("permissions")
        if isinstance(permissions, dict):
            dangerous = []
            for permission, details in permissions.items():
                detail_text = str(details).lower()
                if "dangerous" in detail_text or "high" in detail_text or "critical" in detail_text:
                    dangerous.append(permission)
            if dangerous:
                findings.append(
                    {
                        "title": "Dangerous mobile permissions declared",
                        "category": "mobile",
                        "source": "mobsf",
                        "port": 0,
                        "protocol": "file",
                        "service": "mobile-binary",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": 6.8,
                        "severity": "medium",
                        "evidence": "Dangerous or high-risk permissions reported by MobSF: " + ", ".join(dangerous[:12]),
                        "remediation": "Review each dangerous permission against application requirements and remove any permission that is not essential to business functionality.",
                        "compliance_map": ["MASVS", "OWASP MSTG"],
                        "metadata": {**common_metadata, "dangerous_permissions": dangerous[:20]},
                    }
                )

        url_candidates: list[str] = []
        for key in ("urls", "firebase_urls"):
            value = report.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        candidate = item.get("url") or item.get("path")
                    else:
                        candidate = str(item)
                    if isinstance(candidate, str) and candidate.lower().startswith("http://"):
                        url_candidates.append(candidate)
        if url_candidates:
            findings.append(
                {
                    "title": "Cleartext HTTP endpoint reference found in mobile application",
                    "category": "mobile",
                    "source": "mobsf",
                    "port": 0,
                    "protocol": "file",
                    "service": "mobile-binary",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 8.0,
                    "severity": "high",
                    "evidence": "MobSF reported cleartext HTTP references: " + ", ".join(url_candidates[:8]),
                    "remediation": "Replace cleartext HTTP endpoints with HTTPS and ensure the application blocks insecure transport in production builds.",
                    "compliance_map": ["MASVS", "OWASP MSTG"],
                    "metadata": {**common_metadata, "cleartext_endpoints": url_candidates[:20]},
                }
            )

        secret_candidates = report.get("secrets")
        if isinstance(secret_candidates, list) and secret_candidates:
            snippets: list[str] = []
            for item in secret_candidates[:10]:
                if isinstance(item, dict):
                    location = item.get("file") or item.get("source") or "unknown"
                    secret_value = str(item.get("secret") or item.get("match") or item.get("value") or "")[:24]
                    snippets.append(f"{location}: {secret_value}")
                else:
                    snippets.append(str(item)[:48])
            findings.append(
                {
                    "title": "Hardcoded secret detected in mobile application",
                    "category": "mobile",
                    "source": "mobsf",
                    "port": 0,
                    "protocol": "file",
                    "service": "mobile-binary",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 9.0,
                    "severity": "critical",
                    "evidence": "MobSF identified embedded secret material: " + "; ".join(snippets[:6]),
                    "remediation": "Remove embedded credentials from the application package, rotate exposed secrets, and deliver sensitive values through a protected backend design.",
                    "compliance_map": ["MASVS", "OWASP MSTG"],
                    "metadata": {**common_metadata, "secret_snippets": snippets[:10]},
                }
            )

        code_analysis = report.get("code_analysis")
        if isinstance(code_analysis, dict):
            mobsf_findings = code_analysis.get("findings") or code_analysis.get("issues") or []
            if isinstance(mobsf_findings, list):
                for item in mobsf_findings[:15]:
                    if not isinstance(item, dict):
                        continue
                    severity = str(item.get("severity") or "medium").lower()
                    cvss = 8.5 if severity == "high" else 5.8 if severity == "medium" else 3.2
                    findings.append(
                        {
                            "title": item.get("title") or item.get("issue") or "Mobile code issue",
                            "category": "mobile",
                            "source": "mobsf",
                            "port": 0,
                            "protocol": "file",
                            "service": "mobile-binary",
                            "state": "open",
                            "cve_id": None,
                            "cvss_score": cvss,
                            "severity": "high" if severity == "high" else "medium" if severity == "medium" else "low",
                            "evidence": item.get("description") or item.get("detail") or item.get("evidence") or "MobSF code analysis reported a mobile issue.",
                            "remediation": item.get("recommendation") or item.get("fix") or "Review the affected code path and align the implementation to MASVS and platform security best practices.",
                            "compliance_map": ["MASVS", "OWASP MSTG"],
                            "metadata": {**common_metadata, "file": item.get("file") or item.get("filename"), "rule": item.get("rule") or item.get("issue")},
                        }
                    )

        return findings or self.normalize_results(
            [
                {
                    "title": "MobSF analysis completed with no structured issue sections returned",
                    "cvss": 0.0,
                    "description": "MobSF completed the analysis but did not expose any of the expected issue collections through the API response used by the platform.",
                    "recommendation": "Review the raw MobSF report in the developer view if deeper section-specific parsing is needed for this package.",
                    "file": report.get("file_name") or report.get("app_name"),
                    "rule": "mobsf-generic-report",
                }
            ]
        )


def _probe_service(name: str, base_url: str) -> dict[str, Any]:
    try:
        if name == "zap":
            response = requests.get(
                f"{base_url}/JSON/core/view/version/",
                params={"apikey": os.getenv("ZAP_API_KEY", "zap")},
                timeout=2,
                verify=False,
            )
            response.raise_for_status()
            payload = response.json()
            return {
                "healthy": bool(payload.get("version")),
                "url": base_url,
                "detail": payload.get("version", "reachable"),
            }

        response = requests.get(base_url, timeout=2, verify=False)
        return {"healthy": response.status_code < 500, "url": base_url}
    except (requests.RequestException, ValueError):
        return {"healthy": False, "url": base_url}


def integration_health() -> dict[str, Any]:
    services = {
        "openvas": os.getenv("OPENVAS_API_URL", "http://host.docker.internal:9392"),
        "zap": os.getenv("ZAP_API_URL", "http://zap:8080"),
        "mobsf": os.getenv("MOBSF_API_URL", "http://mobsf:8000"),
        "misp": os.getenv("MISP_FEED_URL", "https://www.misp-project.org/feeds/"),
    }
    return {name: _probe_service(name, base_url) for name, base_url in services.items()}
