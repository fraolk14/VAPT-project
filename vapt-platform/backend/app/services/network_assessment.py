from __future__ import annotations

import json
import ipaddress
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    from datetime import UTC
except ImportError:  # pragma: no cover
    UTC = timezone.utc
from email.utils import parsedate_to_datetime
from typing import Any, Callable
from urllib.parse import urlparse

from app.services.cis_hardening import benchmark_for_os, compliance_tags, infer_os_family, recommendation_for_finding, vendor_reference_links


BASE_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "http-dev",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9000: "admin",
    9200: "elasticsearch",
    9300: "elastic-transport",
    10000: "webmin",
    27017: "mongodb",
}

EXTRA_DEEP_PORTS = {
    1, 7, 9, 13, 17, 19, 26, 37, 42, 49, 67, 68, 69, 70, 79, 81, 82, 83, 84, 88, 106,
    109, 113, 119, 123, 137, 138, 161, 162, 179, 199, 389, 427, 443, 444, 445, 464, 500,
    512, 513, 514, 515, 520, 548, 554, 587, 631, 636, 873, 902, 989, 990, 1025, 1080, 1099,
    11211, 1434, 1723, 1883, 2376, 3128, 3307, 4443, 4848, 5672, 5984, 5985, 5986, 6443,
    7001, 7002, 7199, 7443, 7474, 7777, 8001, 8008, 8020, 8081, 8088, 8090, 8181, 8500,
    8888, 9001, 9042, 9090, 9443, 9999, 15672,
}

DEEP_PORTS = sorted(set(range(1, 1025)) | set(BASE_PORTS) | EXTRA_DEEP_PORTS)
RISKY_EXPOSED_PORTS = {21, 23, 111, 445, 2375, 3389, 5601, 5900, 6379, 9200, 10000, 27017}
HTTP_PORTS = {80, 81, 82, 83, 84, 3000, 5000, 8000, 8001, 8008, 8080, 8081, 8088, 8090, 8181, 8443, 8888, 9000, 9001, 9090, 9200, 9443}
HTTPS_PORTS = {443, 4443, 7443, 8443, 9443}
DISCOVERY_PORTS = [80, 443, 22, 445, 3389, 8080, 8443, 53, 139, 21, 25, 3306, 5432, 6379, 5900]
SERVER_VERSION_PATTERN = re.compile(r"\b([A-Za-z][A-Za-z0-9._-]+)[/_-]([0-9]+(?:\.[0-9]+){0,3})\b")


def _normalize_target(target: str) -> str:
    text = target.strip()
    if "://" in text:
        parsed = urlparse(text)
        return parsed.hostname or text
    return text


def _safe_close(sock: socket.socket | ssl.SSLSocket | None) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass


def _parse_http_response(raw: str) -> tuple[str, dict[str, str], str]:
    head, _, body = raw.partition("\r\n\r\n")
    lines = [line for line in head.splitlines() if line.strip()]
    status_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status_line, headers, body


def _extract_html_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:120]


def _http_request(host: str, port: int, path: str, tls: bool) -> dict[str, Any]:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Accept: */*\r\n"
        f"User-Agent: VAPTICOM\r\n\r\n"
    )
    sock: socket.socket | None = None
    conn: socket.socket | ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=4.0)
        conn = sock
        tls_metadata: dict[str, Any] = {}
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = context.wrap_socket(sock, server_hostname=host)
            cert = conn.getpeercert()
            tls_metadata = {
                "tls_version": conn.version(),
                "cipher": (conn.cipher() or ("", "", 0))[0],
                "certificate_subject": dict(item[0] for item in cert.get("subject", [])) if cert else {},
                "certificate_issuer": dict(item[0] for item in cert.get("issuer", [])) if cert else {},
                "certificate_not_after": cert.get("notAfter") if cert else None,
            }
        conn.settimeout(3.0)
        conn.sendall(request.encode("ascii", errors="ignore"))
        chunks: list[bytes] = []
        while True:
            try:
                chunk = conn.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(part) for part in chunks) > 24576:
                break
        data = b"".join(chunks).decode("utf-8", errors="ignore")
        status_line, headers, body = _parse_http_response(data)
        return {
            "path": path,
            "status_line": status_line,
            "headers": headers,
            "title": _extract_html_title(body),
            "body_excerpt": body[:1200],
            "banner": headers.get("server", "") or data[:300],
            **tls_metadata,
        }
    finally:
        _safe_close(conn if conn is not sock else None)
        _safe_close(sock)


def _generic_banner_probe(host: str, port: int) -> str:
    sock = socket.create_connection((host, port), timeout=2.5)
    try:
        sock.settimeout(2.0)
        try:
            data = sock.recv(512).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            data = ""
        return data
    finally:
        _safe_close(sock)


def _redis_probe(host: str, port: int) -> dict[str, Any]:
    sock = socket.create_connection((host, port), timeout=3.0)
    try:
        sock.settimeout(2.5)
        sock.sendall(b"INFO\r\n")
        data = sock.recv(2048).decode("utf-8", errors="ignore")
        return {"response": data[:800]}
    finally:
        _safe_close(sock)


def _docker_probe(host: str, port: int) -> dict[str, Any]:
    return _http_request(host, port, "/version", tls=False)


def _elasticsearch_probe(host: str, port: int) -> dict[str, Any]:
    return _http_request(host, port, "/", tls=False)


def _banner_version_refs(banner: str) -> list[str]:
    return [f"{product}/{version}" for product, version in SERVER_VERSION_PATTERN.findall(banner or "")][:6]


def _infer_service(service_hint: str, banner: str) -> str:
    banner_lower = (banner or "").lower()
    if "openresty" in banner_lower or "nginx" in banner_lower:
        return "nginx"
    if "apache" in banner_lower:
        return "apache"
    if "postgres" in banner_lower:
        return "postgresql"
    if "redis" in banner_lower:
        return "redis"
    if "openssh" in banner_lower or banner_lower.startswith("ssh-"):
        return "ssh"
    if "microsoft-iis" in banner_lower:
        return "iis"
    if "docker" in banner_lower:
        return "docker"
    if "elasticsearch" in banner_lower:
        return "elasticsearch"
    return service_hint


def _base_finding(
    *,
    host: str,
    port: int,
    service: str,
    title: str,
    severity: str,
    cvss_score: float,
    evidence: str,
    remediation: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    os_family = infer_os_family(
        service=service,
        banner=str(metadata.get("banner", "")),
        port=port,
        title=title,
        evidence=evidence,
    )
    hardening_recommendation = recommendation_for_finding(title=title, service=service, os_family=os_family)
    references = metadata.get("references") or vendor_reference_links(service=service, title=title)
    merged_metadata = {
        "host": host,
        "os_family": os_family,
        "cis_benchmark": metadata.get("cis_benchmark") or benchmark_for_os(os_family),
        "hardening_recommendation": hardening_recommendation,
        "references": references,
        **metadata,
    }
    return {
        "title": title,
        "category": "network",
        "source": "network-db",
        "port": port,
        "protocol": "tcp",
        "service": service,
        "state": "open",
        "cve_id": None,
        "cvss_score": cvss_score,
        "severity": severity,
        "confidence": 0.9,
        "evidence": evidence,
        "remediation": remediation or hardening_recommendation,
        "compliance_map": compliance_tags(os_family=os_family, service=service, title=title, evidence=evidence),
        "metadata": merged_metadata,
    }


def _certificate_expiry_days(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expiry = parsedate_to_datetime(not_after)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return int((expiry - datetime.now(UTC)).total_seconds() // 86400)
    except Exception:
        return None


def _generic_exposure_finding(host: str, port: int, service: str, banner: str, metadata: dict[str, Any]) -> dict[str, Any]:
    severity = "medium" if port in {1433, 1521, 2049, 3306, 5432, 6379, 9200} else "low"
    score = 6.4 if severity == "medium" else 3.8
    return _base_finding(
        host=host,
        port=port,
        service=service,
        title=f"Exposed {service or 'network'} service on port {port}",
        severity=severity,
        cvss_score=score,
        evidence=banner or f"TCP connection to {host}:{port} succeeded.",
        remediation=f"Validate whether {service} on port {port} must be reachable, restrict exposure to trusted networks, and patch the underlying software.",
        metadata={**metadata, "banner_versions": _banner_version_refs(banner)},
    )


def _risky_service_findings(host: str, port: int, service: str, banner: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    if port not in RISKY_EXPOSED_PORTS:
        return []
    titles = {
        21: "FTP service exposed",
        23: "Telnet service exposed",
        111: "RPC service exposed",
        445: "SMB service exposed",
        2375: "Unauthenticated Docker API exposure",
        3389: "RDP service exposed",
        5601: "Kibana administrative surface exposed",
        5900: "VNC service exposed",
        6379: "Redis service exposed",
        9200: "Elasticsearch HTTP API exposed",
        10000: "Webmin administrative interface exposed",
        27017: "MongoDB service exposed",
    }
    return [
        _base_finding(
            host=host,
            port=port,
            service=service,
            title=titles.get(port, f"Exposed {service} service on port {port}"),
            severity="high",
            cvss_score=8.1 if port in {23, 2375, 6379, 9200} else 7.5,
            evidence=banner or f"The service on {host}:{port} accepted a connection.",
            remediation=f"Restrict {service} on port {port} to trusted networks, add authentication where possible, and validate business need for exposure.",
            metadata=metadata,
        )
    ]


def _http_security_findings(host: str, port: int, service: str, metadata: dict[str, Any], probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root_probe = next((probe for probe in probes if probe["path"] == "/"), probes[0] if probes else {})
    headers = root_probe.get("headers") or {}
    title = root_probe.get("title")
    status_line = root_probe.get("status_line") or "HTTP response received"
    body_excerpt = root_probe.get("body_excerpt") or ""
    base_metadata = {
        **metadata,
        "page_title": title,
        "security_headers": headers,
        "banner_versions": _banner_version_refs(root_probe.get("banner", "")),
        "http_paths": [{"path": probe["path"], "status": probe.get("status_line", "")} for probe in probes],
    }
    evidence_prefix = f"{status_line}. " + (f"Page title: {title}. " if title else "")

    if port not in HTTPS_PORTS:
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Cleartext HTTP service exposed",
                severity="medium",
                cvss_score=5.3,
                evidence=evidence_prefix + "The service responds over unencrypted HTTP.",
                remediation="Enforce HTTPS for sensitive routes and disable unnecessary cleartext listeners.",
                metadata=base_metadata,
            )
        )
    if port in HTTPS_PORTS and "strict-transport-security" not in headers:
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="HTTPS service missing HSTS",
                severity="medium",
                cvss_score=5.4,
                evidence=evidence_prefix + "Strict-Transport-Security was not present in the response.",
                remediation="Add an HSTS policy with a suitable max-age and includeSubDomains setting where appropriate.",
                metadata=base_metadata,
            )
        )
    if "content-security-policy" not in headers:
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Web response missing Content-Security-Policy",
                severity="medium",
                cvss_score=5.8,
                evidence=evidence_prefix + "Content-Security-Policy was not present in the response.",
                remediation="Define a restrictive Content-Security-Policy to reduce untrusted script execution and content injection exposure.",
                metadata=base_metadata,
            )
        )
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Clickjacking protection is missing",
                severity="low",
                cvss_score=3.7,
                evidence=evidence_prefix + "Neither X-Frame-Options nor CSP frame-ancestors controls were observed.",
                remediation="Set X-Frame-Options or CSP frame-ancestors to prevent untrusted framing.",
                metadata=base_metadata,
            )
        )
    if "x-content-type-options" not in headers:
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="MIME sniffing protection is missing",
                severity="low",
                cvss_score=3.1,
                evidence=evidence_prefix + "X-Content-Type-Options: nosniff was not present.",
                remediation="Add X-Content-Type-Options: nosniff to reduce browser content sniffing risk.",
                metadata=base_metadata,
            )
        )
    if "server" in headers and re.search(r"/\d", headers["server"]):
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Server version disclosure detected",
                severity="low",
                cvss_score=2.9,
                evidence=evidence_prefix + f"The Server header discloses version information: {headers['server']}.",
                remediation="Reduce banner verbosity where feasible and patch the disclosed server version promptly.",
                metadata=base_metadata,
            )
        )
    if "index of /" in body_excerpt.lower():
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Directory listing appears enabled",
                severity="medium",
                cvss_score=5.0,
                evidence=evidence_prefix + "The response body included an 'Index of /' style directory listing.",
                remediation="Disable directory listing and restrict access to file indexes and browsable content paths.",
                metadata=base_metadata,
            )
        )

    actuator_probe = next((probe for probe in probes if probe["path"] == "/actuator/health"), None)
    if actuator_probe and actuator_probe.get("status_line", "").startswith("HTTP/1.1 200"):
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Spring actuator endpoint exposed",
                severity="high",
                cvss_score=7.5,
                evidence=f"{actuator_probe['status_line']}. /actuator/health responded successfully and may expose runtime health information without access control.",
                remediation="Restrict actuator endpoints to trusted operators, require authentication, or disable unnecessary actuator exposure.",
                metadata={**base_metadata, "exposed_path": "/actuator/health"},
            )
        )

    server_status_probe = next((probe for probe in probes if probe["path"] == "/server-status"), None)
    if server_status_probe and server_status_probe.get("status_line", "").startswith("HTTP/1.1 200"):
        findings.append(
            _base_finding(
                host=host,
                port=port,
                service=service,
                title="Web server status endpoint exposed",
                severity="medium",
                cvss_score=5.9,
                evidence=f"{server_status_probe['status_line']}. /server-status was accessible and may leak operational detail.",
                remediation="Restrict status and diagnostics endpoints to local or administrative networks only.",
                metadata={**base_metadata, "exposed_path": "/server-status"},
            )
        )

    return findings


def _tls_findings(host: str, port: int, service: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tls_version = (metadata.get("tls_version") or "").upper()
    subject = metadata.get("certificate_subject") or {}
    issuer = metadata.get("certificate_issuer") or {}
    expiry_days = _certificate_expiry_days(metadata.get("certificate_not_after"))
    base_metadata = {**metadata, "certificate_expiry_days": expiry_days, "banner_versions": _banner_version_refs(metadata.get("banner", ""))}
    evidence_prefix = f"TLS negotiation completed using {tls_version or 'an unidentified version'}."

    if tls_version in {"TLSV1", "TLSV1.1"}:
        findings.append(_base_finding(host=host, port=port, service=service, title="Legacy TLS protocol negotiated", severity="high", cvss_score=7.4, evidence=evidence_prefix + " The service accepted an obsolete TLS protocol version.", remediation="Disable TLS 1.0 and TLS 1.1 and enforce TLS 1.2 or TLS 1.3.", metadata=base_metadata))
    if subject and issuer and subject == issuer:
        findings.append(_base_finding(host=host, port=port, service=service, title="Self-signed TLS certificate detected", severity="medium", cvss_score=5.9, evidence=evidence_prefix + " The certificate subject matches the issuer, indicating a self-signed certificate.", remediation="Replace the self-signed certificate with one issued by a trusted CA appropriate for the environment.", metadata=base_metadata))
    if expiry_days is not None and expiry_days < 0:
        findings.append(_base_finding(host=host, port=port, service=service, title="Expired TLS certificate detected", severity="high", cvss_score=7.5, evidence=evidence_prefix + f" The certificate expired {abs(expiry_days)} days ago.", remediation="Renew and deploy a valid certificate immediately, then validate trust and automated monitoring.", metadata=base_metadata))
    elif expiry_days is not None and expiry_days <= 30:
        findings.append(_base_finding(host=host, port=port, service=service, title="TLS certificate nearing expiry", severity="medium", cvss_score=5.0, evidence=evidence_prefix + f" The certificate expires in {expiry_days} days.", remediation="Schedule certificate renewal before expiry and verify renewal automation or alerting.", metadata=base_metadata))
    if metadata.get("cipher") and any(token in metadata["cipher"].upper() for token in ["RC4", "3DES", "DES", "NULL"]):
        findings.append(_base_finding(host=host, port=port, service=service, title="Weak TLS cipher observed", severity="high", cvss_score=7.0, evidence=evidence_prefix + f" Negotiated cipher: {metadata['cipher']}.", remediation="Disable weak cipher suites and prefer modern AEAD ciphers with forward secrecy.", metadata=base_metadata))
    return findings


def _service_specific_findings(host: str, port: int, service: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if port == 6379:
        try:
            result = _redis_probe(host, port)
            response = result.get("response", "")
            if response.startswith("# Server") or "redis_version" in response:
                findings.append(
                    _base_finding(
                        host=host,
                        port=port,
                        service=service,
                        title="Redis responds without authentication challenge",
                        severity="critical",
                        cvss_score=9.1,
                        evidence="A direct INFO request returned Redis server data without an authentication error.",
                        remediation="Require Redis authentication, enable protected mode, and restrict exposure to trusted administrative networks.",
                        metadata={**metadata, "service_probe": "INFO", "service_response": response[:800]},
                    )
                )
        except Exception:
            pass
    elif port == 2375:
        try:
            result = _docker_probe(host, port)
            if result.get("status_line", "").startswith("HTTP/1.1 200"):
                findings.append(
                    _base_finding(
                        host=host,
                        port=port,
                        service=service,
                        title="Docker daemon API accessible without transport security",
                        severity="critical",
                        cvss_score=9.8,
                        evidence=f"{result['status_line']}. /version responded from the Docker daemon API.",
                        remediation="Disable plaintext Docker TCP exposure, bind locally, or require mTLS and network restriction.",
                        metadata={**metadata, "service_probe": "/version", "service_response": result.get("body_excerpt", "")},
                    )
                )
        except Exception:
            pass
    elif port == 9200:
        try:
            result = _elasticsearch_probe(host, port)
            if "you know, for search" in (result.get("body_excerpt") or "").lower():
                findings.append(
                    _base_finding(
                        host=host,
                        port=port,
                        service=service,
                        title="Elasticsearch API exposed without access controls",
                        severity="critical",
                        cvss_score=9.4,
                        evidence=f"{result['status_line']}. The root Elasticsearch API responded with cluster identification data.",
                        remediation="Require authentication, bind Elasticsearch to trusted interfaces only, and block direct public access.",
                        metadata={**metadata, "service_probe": "/", "service_response": result.get("body_excerpt", "")},
                    )
                )
        except Exception:
            pass
    return findings


def _http_probe_bundle(host: str, port: int, tls: bool) -> list[dict[str, Any]]:
    paths = ["/", "/robots.txt", "/.well-known/security.txt", "/server-status", "/actuator/health"]
    results: list[dict[str, Any]] = []
    for path in paths:
        try:
            results.append(_http_request(host, port, path, tls))
        except Exception:
            continue
    return results


def _probe_port(host: str, port: int, service_hint: str) -> list[dict[str, Any]]:
    try:
        with socket.create_connection((host, port), timeout=1.2):
            pass
    except OSError:
        return []

    probe_metadata: dict[str, Any] = {"host": host}
    banner = ""
    service = service_hint
    http_probes: list[dict[str, Any]] = []

    try:
        if port in HTTP_PORTS:
            http_probes = _http_probe_bundle(host, port, tls=port in HTTPS_PORTS)
            if http_probes:
                banner = http_probes[0].get("banner", "")
                probe_metadata.update(http_probes[0])
        else:
            banner = _generic_banner_probe(host, port)
    except Exception as exc:
        probe_metadata["probe_error"] = str(exc)

    service = _infer_service(service_hint, banner)
    probe_metadata["banner"] = banner
    probe_metadata["banner_versions"] = _banner_version_refs(banner)
    probe_metadata["os_family"] = infer_os_family(service=service, banner=banner, port=port)
    probe_metadata["cis_benchmark"] = benchmark_for_os(probe_metadata["os_family"])
    probe_metadata["references"] = vendor_reference_links(service=service, title=f"{service} on port {port}")
    if port in HTTPS_PORTS:
        probe_metadata["tls_detected"] = True

    findings: list[dict[str, Any]] = []
    findings.extend(_risky_service_findings(host, port, service, banner, probe_metadata))
    findings.extend(_service_specific_findings(host, port, service, probe_metadata))

    generic_allowed = service in {"apache", "nginx", "iis", "postgresql", "mysql", "mssql", "oracle", "redis", "elasticsearch", "docker", "kibana", "webmin"} or port in RISKY_EXPOSED_PORTS
    if generic_allowed and not any(item["title"].lower().startswith("exposed ") for item in findings):
        findings.append(_generic_exposure_finding(host, port, service, banner, probe_metadata))

    if http_probes:
        findings.extend(_http_security_findings(host, port, service, probe_metadata, http_probes))
    if port in HTTPS_PORTS:
        findings.extend(_tls_findings(host, port, service, probe_metadata))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for item in findings:
        key = (item["title"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _is_cidr_target(target: str) -> bool:
    try:
        ipaddress.ip_network(_normalize_target(target), strict=False)
        return "/" in _normalize_target(target)
    except ValueError:
        return False


def _quick_host_is_active(host: str) -> bool:
    for port in DISCOVERY_PORTS:
        try:
            with socket.create_connection((host, port), timeout=0.45):
                return True
        except OSError:
            continue
    return False


def discover_active_hosts(network_target: str, progress_callback: Callable[[int, dict[str, Any]], None] | None = None) -> list[str]:
    network = ipaddress.ip_network(_normalize_target(network_target), strict=False)
    hosts = [str(host) for host in network.hosts()]
    if not hosts and network.num_addresses == 1:
        hosts = [str(network.network_address)]
    active_hosts: list[str] = []
    completed = 0

    def emit(progress: int, detail: dict[str, Any]) -> None:
        if progress_callback:
            progress_callback(progress, detail)

    emit(5, {"phase": "host-discovery", "message": f"Discovering active hosts in {network} across {len(hosts)} usable addresses."})
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(_quick_host_is_active, host): host for host in hosts}
        for future in as_completed(futures):
            completed += 1
            host = futures[future]
            try:
                if future.result():
                    active_hosts.append(host)
            except Exception:
                pass
            if completed % 16 == 0 or completed == len(hosts):
                emit(
                    min(24, 5 + int((completed / max(len(hosts), 1)) * 19)),
                    {
                        "phase": "host-discovery",
                        "message": f"Discovery checked {completed} of {len(hosts)} addresses and found {len(active_hosts)} active host(s).",
                        "active_hosts": active_hosts,
                    },
                )
    return sorted(active_hosts, key=lambda item: ipaddress.ip_address(item))


def run_network_block_assessment(target: str, progress_callback: Callable[[int, dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    active_hosts = discover_active_hosts(target, progress_callback)
    findings: list[dict[str, Any]] = []

    def emit(progress: int, detail: dict[str, Any]) -> None:
        if progress_callback:
            progress_callback(progress, detail)

    if not active_hosts:
        emit(95, {"phase": "analysis", "message": f"No active hosts were confirmed in {target}."})
        return [
            {
                "title": "No active hosts detected in network block",
                "category": "network",
                "source": "network-db",
                "port": 0,
                "protocol": "tcp",
                "service": "network-block",
                "state": "closed",
                "cve_id": None,
                "cvss_score": 0.0,
                "severity": "info",
                "confidence": 0.94,
                "evidence": f"Discovery did not confirm active hosts in {target} using the configured TCP discovery probes.",
                "remediation": "Confirm routing, firewall policy, and scan placement. If hosts block TCP probes, use authenticated agents or allow scanner discovery probes.",
                "compliance_map": ["NIST RA-5"],
                "metadata": {"host": str(ipaddress.ip_network(_normalize_target(target), strict=False).network_address), "network_block": target, "active_hosts": []},
            }
        ]

    total = len(active_hosts)
    for index, host in enumerate(active_hosts, start=1):
        start_progress = 25 + int(((index - 1) / total) * 65)

        def host_progress(inner_progress: int, detail: dict[str, Any], *, host_value: str = host, offset: int = start_progress) -> None:
            mapped = min(90, offset + int((inner_progress / 100) * max(1, 65 // total)))
            emit(mapped, {**detail, "host": host_value, "active_hosts": active_hosts, "message": f"{host_value}: {detail.get('message', 'Scanning host')}"})

        findings.extend(run_network_assessment(host, progress_callback=host_progress))

    host_os_summary: dict[str, str] = {}
    for item in findings:
        metadata = item.get("metadata") or {}
        host_value = metadata.get("host")
        os_family = metadata.get("os_family")
        if host_value and os_family and str(host_value) not in host_os_summary:
            host_os_summary[str(host_value)] = str(os_family)

    if host_os_summary:
        findings.insert(
            0,
            {
                "title": "Active hosts discovered with operating-system fingerprint hints",
                "category": "network",
                "source": "network-db",
                "port": 0,
                "protocol": "tcp",
                "service": "network-block",
                "state": "open",
                "cve_id": None,
                "cvss_score": 0.0,
                "severity": "info",
                "confidence": 0.82,
                "evidence": "; ".join(f"{host} -> {os_family}" for host, os_family in sorted(host_os_summary.items()))[:1800],
                "remediation": "Review discovered hosts, confirm operating-system ownership, and apply CIS-aligned hardening to internet-facing or sensitive systems before re-testing.",
                "compliance_map": ["NIST RA-5", "CIS Controls 1", "CIS Controls 7"],
                "metadata": {
                    "host": str(ipaddress.ip_network(_normalize_target(target), strict=False).network_address),
                    "network_block": target,
                    "active_hosts": active_hosts,
                    "host_os_summary": host_os_summary,
                    "references": ["https://www.cisecurity.org/cis-benchmarks"],
                },
            },
        )

    emit(95, {"phase": "analysis", "message": f"Network block scan completed for {target}: {len(active_hosts)} active host(s), {len(findings)} finding(s).", "active_hosts": active_hosts})
    return findings


def run_network_assessment(target: str, progress_callback: Callable[[int, dict[str, Any]], None] | None = None) -> list[dict[str, Any]]:
    if _is_cidr_target(target):
        return run_network_block_assessment(target, progress_callback)

    host = _normalize_target(target)
    findings: list[dict[str, Any]] = []
    total = len(DEEP_PORTS)
    completed = 0

    def emit(progress: int, detail: dict[str, Any]) -> None:
        if progress_callback:
            progress_callback(progress, detail)

    emit(10, {"phase": "port-sweep", "message": f"Starting deep network assessment across {total} ports."})

    with ThreadPoolExecutor(max_workers=24) as pool:
        futures = {
            pool.submit(_probe_port, host, port, BASE_PORTS.get(port, "unknown")): port
            for port in DEEP_PORTS
        }
        for future in as_completed(futures):
            completed += 1
            try:
                result = future.result()
            except Exception:
                result = []
            findings.extend(result)
            if completed % 64 == 0 or completed == total:
                progress = min(80, 10 + int((completed / total) * 70))
                emit(progress, {"phase": "port-sweep", "message": f"Deep sweep checked {completed} of {total} ports.", "open_findings": len(findings)})

    if not findings:
        emit(95, {"phase": "analysis", "message": "No exposed services were confirmed during the deep sweep."})
        findings.append(
            {
                "title": "No exposed services detected during deep assessment",
                "category": "network",
                "source": "network-db",
                "port": 0,
                "protocol": "tcp",
                "service": "host",
                "state": "closed",
                "cve_id": None,
                "cvss_score": 0.0,
                "severity": "info",
                "confidence": 0.95,
                "evidence": f"The deep assessment did not confirm exposed services on {host} across the configured port set.",
                "remediation": "If the host should expose services, validate network routing, firewall policy, scanner placement, and whether authenticated assessment is required.",
                "compliance_map": ["NIST RA-5"],
                "metadata": {"host": host, "scan_mode": "deep-direct", "ports_tested": total},
            }
        )

    emit(95, {"phase": "analysis", "message": f"Deep assessment finished evidence collection with {len(findings)} evidence-backed findings."})
    return sorted(findings, key=lambda item: (item["port"], item["title"]))
