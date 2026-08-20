"""
nmap_scanner.py
───────────────
Nmap CLI integration for the VAPT network scan engine.

Runs `nmap -sV -Pn -T4 --script <scripts> -oX -` against the target,
parses the XML output, and returns normalized finding dicts that are
compatible with the network_assessment finding schema.

This is designed to run *in parallel* with the Python socket scanner
in network_assessment.py and have its results merged/correlated by
correlate_network_findings().
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

# ── CVE pattern (same as integrations.py) ────────────────────────────────────
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ── NSE scripts to run (conservative – no intrusive/DoS scripts) ─────────────
NSE_SCRIPTS = ",".join([
    "banner",
    "http-title",
    "http-headers",
    "http-methods",
    "http-server-header",
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssh-hostkey",
    "ssh2-enum-algos",
    "ftp-anon",
    "ftp-syst",
    "smtp-commands",
    "smtp-open-relay",
    "pop3-capabilities",
    "imap-capabilities",
    "rdp-enum-encryption",
    "ms-sql-info",
    "mysql-info",
    "mongodb-info",
    "redis-info",
    "memcached-info",
    "ldap-rootdse",
    "dns-recursion",
    "snmp-info",
    "http-auth-finder",
    "http-open-redirect",
    "http-cors",
    "http-csrf",
    "http-internal-ip-disclosure",
    "http-php-version",
])

# ── CVSS score heuristics ─────────────────────────────────────────────────────
_SEVERITY_MAP = {
    "critical": ("critical", 9.5),
    "high":     ("high",     7.5),
    "medium":   ("medium",   5.0),
    "low":      ("low",      3.0),
    "info":     ("info",     0.0),
}

_RISKY_SERVICES = {
    "telnet", "ftp", "rsh", "rlogin", "rexec", "tftp",
    "redis", "mongodb", "memcached", "elasticsearch",
    "docker", "vnc",
}

_COMPLIANCE_DEFAULTS = ["NIST RA-5", "OWASP ASVS V4", "CIS Controls 7"]


def _safe_text(element: ET.Element | None, path: str, default: str = "") -> str:
    if element is None:
        return default
    node = element.find(path)
    return (node.text or default).strip() if node is not None else default


def _extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in CVE_PATTERN.findall(text)})


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _service_severity(port: int, service_name: str, state: str) -> tuple[str, float]:
    """Heuristic CVSS for an open port based on port/service name."""
    if state != "open":
        return "info", 0.0
    svc = (service_name or "").lower()
    if any(r in svc for r in _RISKY_SERVICES):
        return "high", 7.5
    if port in {23, 513, 514}:          # telnet, rsh, rexec
        return "critical", 9.1
    if port in {2375, 2376}:            # Docker daemon
        return "critical", 9.8
    if port in {21}:                    # FTP
        return "high", 7.5
    if port in {3389, 5900}:            # RDP, VNC
        return "high", 7.5
    if port in {3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 9042}:
        return "medium", 6.5
    return "low", 3.8


def _script_severity(script_id: str, output: str) -> tuple[str, float]:
    """Extract severity from NSE script output."""
    out_low = output.lower()
    if "anonymous" in out_low and "ftp" in script_id:
        return "high", 7.5
    if "open-relay" in script_id:
        return "high", 7.5
    if "cors" in script_id and ("*" in output or "null" in out_low):
        return "medium", 6.5
    if "csrf" in script_id:
        return "medium", 5.9
    if "redirect" in script_id:
        return "medium", 5.4
    if "internal-ip" in script_id:
        return "medium", 5.0
    if "php-version" in script_id:
        return "low", 3.1
    if "auth-finder" in script_id and "no auth" in out_low:
        return "high", 7.5
    return "info", 0.0


def _make_finding(
    *,
    host: str,
    port: int,
    protocol: str,
    service: str,
    title: str,
    severity: str,
    cvss_score: float,
    evidence: str,
    remediation: str,
    cve_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    source: str = "nmap",
) -> dict[str, Any]:
    return {
        "title": title,
        "category": "network",
        "source": source,
        "port": port,
        "protocol": protocol,
        "service": service,
        "state": "open",
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "severity": severity,
        "confidence": 0.92,
        "evidence": evidence,
        "remediation": remediation,
        "compliance_map": _COMPLIANCE_DEFAULTS[:],
        "metadata": {
            "host": host,
            "scanner": "nmap",
            **(metadata or {}),
        },
    }


def _parse_host(host_elem: ET.Element) -> list[dict[str, Any]]:
    """Parse a single <host> element from Nmap XML output."""
    findings: list[dict[str, Any]] = []

    # Resolve best host address
    addr_elem = host_elem.find("address[@addrtype='ipv4']")
    if addr_elem is None:
        addr_elem = host_elem.find("address")
    host = addr_elem.attrib.get("addr", "unknown") if addr_elem is not None else "unknown"

    # Hostname (if any)
    hn_elem = host_elem.find("hostnames/hostname[@type='PTR']")
    if hn_elem is None:
        hn_elem = host_elem.find("hostnames/hostname")
    hostname = hn_elem.attrib.get("name", "") if hn_elem is not None else ""

    ports_elem = host_elem.find("ports")
    if ports_elem is None:
        return findings

    for port_elem in ports_elem.findall("port"):
        port_num = int(port_elem.attrib.get("portid", "0"))
        proto = port_elem.attrib.get("protocol", "tcp")

        state_elem = port_elem.find("state")
        state = state_elem.attrib.get("state", "unknown") if state_elem is not None else "unknown"
        if state not in {"open", "open|filtered"}:
            continue

        svc_elem = port_elem.find("service")
        svc_name = svc_elem.attrib.get("name", "unknown") if svc_elem is not None else "unknown"
        svc_product = svc_elem.attrib.get("product", "") if svc_elem is not None else ""
        svc_version = svc_elem.attrib.get("version", "") if svc_elem is not None else ""
        svc_extra = svc_elem.attrib.get("extrainfo", "") if svc_elem is not None else ""
        tunnel = svc_elem.attrib.get("tunnel", "") if svc_elem is not None else ""

        full_version = " ".join(filter(None, [svc_product, svc_version, svc_extra])).strip()
        display_service = full_version or svc_name

        # Base port/service finding
        severity, cvss_score = _service_severity(port_num, svc_name, state)
        evidence_parts = [f"Nmap confirmed port {port_num}/{proto} is open."]
        if full_version:
            evidence_parts.append(f"Service fingerprint: {full_version}.")
        if hostname:
            evidence_parts.append(f"Hostname: {hostname}.")

        findings.append(_make_finding(
            host=host,
            port=port_num,
            protocol=proto,
            service=display_service or svc_name,
            title=f"Open port {port_num}/{proto} – {display_service or svc_name}",
            severity=severity,
            cvss_score=cvss_score,
            evidence=" ".join(evidence_parts),
            remediation=(
                f"Review whether {svc_name} on port {port_num} should be reachable. "
                "Restrict to trusted networks, require authentication, and keep the service patched."
            ),
            metadata={
                "nmap_service": svc_name,
                "nmap_product": svc_product,
                "nmap_version": svc_version,
                "nmap_extrainfo": svc_extra,
                "nmap_tunnel": tunnel,
                "hostname": hostname,
            },
        ))

        # ── Parse NSE script output ───────────────────────────────────────────
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.attrib.get("id", "")
            script_out = script_elem.attrib.get("output", "").strip()
            if not script_out or script_out == "ERROR":
                continue

            # CVEs embedded in script output
            cves = _extract_cves(script_out)
            cve_str = ", ".join(cves) if cves else None

            # Skip pure-info scripts with no content
            if script_id in {"banner", "http-server-header"} and len(script_out) < 8:
                continue

            # Severity guess from script content
            scr_severity, scr_cvss = _script_severity(script_id, script_out)

            # Override for specific high-value scripts
            if script_id == "ftp-anon" and "anonymous ftp login allowed" in script_out.lower():
                scr_severity, scr_cvss = "high", 7.5

            if script_id == "ssl-enum-ciphers":
                if "sslv2" in script_out.lower() or "sslv3" in script_out.lower():
                    scr_severity, scr_cvss = "high", 7.5
                elif "tlsv1.0" in script_out.lower():
                    scr_severity, scr_cvss = "medium", 5.9
                else:
                    scr_severity, scr_cvss = "info", 0.0

            if script_id == "http-methods":
                dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in script_out.upper()]
                if dangerous:
                    scr_severity, scr_cvss = "medium", 5.3

            # Suppress pure-info NSE outputs with no severity
            if scr_severity == "info" and not cves and script_id not in {
                "http-title", "ssl-cert", "ssh-hostkey", "http-cors", "http-csrf",
                "http-auth-finder", "smtp-open-relay", "redis-info", "mongodb-info",
                "mysql-info", "ms-sql-info", "ftp-anon", "http-methods",
                "http-open-redirect", "http-internal-ip-disclosure",
            }:
                continue

            findings.append(_make_finding(
                host=host,
                port=port_num,
                protocol=proto,
                service=display_service or svc_name,
                title=f"NSE/{script_id} – port {port_num}",
                severity=scr_severity,
                cvss_score=scr_cvss,
                evidence=f"Nmap NSE script '{script_id}' output on port {port_num}: {script_out[:800]}",
                remediation=(
                    f"Review the '{script_id}' finding on {host}:{port_num} and apply "
                    "appropriate hardening, authentication, or service configuration changes."
                ),
                cve_id=cve_str,
                metadata={
                    "script_id": script_id,
                    "script_output": script_out[:1200],
                    "hostname": hostname,
                    "cve_refs": cves,
                },
            ))

    # ── OS detection ──────────────────────────────────────────────────────────
    os_match = host_elem.find(".//osmatch")
    if os_match is not None:
        os_name = os_match.attrib.get("name", "")
        os_accuracy = os_match.attrib.get("accuracy", "")
        if os_name:
            findings.append(_make_finding(
                host=host,
                port=0,
                protocol="tcp",
                service="os-detection",
                title=f"OS fingerprint: {os_name}",
                severity="info",
                cvss_score=0.0,
                evidence=f"Nmap OS detection identified the host as '{os_name}' (accuracy: {os_accuracy}%).",
                remediation="Validate OS version currency and apply vendor-recommended hardening baselines.",
                metadata={"os_name": os_name, "os_accuracy": os_accuracy, "hostname": hostname},
            ))

    return findings


def parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
    """Parse raw Nmap XML string into normalized findings."""
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        return [{
            "title": "Nmap XML parse error",
            "category": "network",
            "source": "nmap",
            "port": 0,
            "protocol": "tcp",
            "service": "nmap",
            "state": "error",
            "cve_id": None,
            "cvss_score": 0.0,
            "severity": "info",
            "confidence": 0.0,
            "evidence": f"Failed to parse Nmap XML output: {exc}",
            "remediation": "Check Nmap is installed and the target is reachable.",
            "compliance_map": [],
            "metadata": {"scanner": "nmap", "parse_error": str(exc)},
        }]

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is not None and status.attrib.get("state") == "down":
            continue
        findings.extend(_parse_host(host_elem))

    return findings


def run_nmap_scan(
    target: str,
    ports: str = "1-1024,1433,1521,2375,3000,3306,3389,5432,5601,5900,6379,8080,8443,8888,9000,9200,9300,10000,27017",
    timing: str = "T4",
    extra_args: list[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Execute Nmap against `target` and return (findings, metadata).

    Returns an error finding if Nmap is not installed or the scan fails.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        return [{
            "title": "Nmap not available on this system",
            "category": "network",
            "source": "nmap",
            "port": 0, "protocol": "tcp", "service": "nmap", "state": "error",
            "cve_id": None, "cvss_score": 0.0, "severity": "info", "confidence": 0.0,
            "evidence": "Nmap binary was not found. Install nmap in the API container.",
            "remediation": "Add 'nmap' to the API Dockerfile RUN apt-get install line.",
            "compliance_map": [], "metadata": {"scanner": "nmap"},
        }], {"nmap_available": False}

    cmd = [
        nmap_bin,
        "-sV",           # service version detection
        "-Pn",           # skip host discovery ping (treat all hosts as up)
        f"-{timing}",    # timing template (T4 = aggressive)
        "--script", NSE_SCRIPTS,
        "-p", ports,
        "-oX", "-",      # XML output to stdout
        "--open",        # only show open ports
        target,
    ]
    if extra_args:
        cmd.extend(extra_args)

    metadata: dict[str, Any] = {
        "nmap_available": True,
        "nmap_cmd": " ".join(cmd),
        "target": target,
    }

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,   # 10-minute hard ceiling
        )
        metadata["nmap_returncode"] = result.returncode
        metadata["nmap_stderr"] = result.stderr[:500] if result.stderr else ""

        if result.returncode not in (0, 1):  # nmap exits 1 when no hosts found
            return [{
                "title": "Nmap scan execution error",
                "category": "network",
                "source": "nmap",
                "port": 0, "protocol": "tcp", "service": "nmap", "state": "error",
                "cve_id": None, "cvss_score": 0.0, "severity": "info", "confidence": 0.0,
                "evidence": f"Nmap exited with code {result.returncode}. stderr: {result.stderr[:400]}",
                "remediation": "Check target reachability and Nmap permissions.",
                "compliance_map": [], "metadata": {**metadata, "scanner": "nmap"},
            }], metadata

        findings = parse_nmap_xml(result.stdout)
        metadata["nmap_finding_count"] = len(findings)
        return findings, metadata

    except subprocess.TimeoutExpired:
        return [{
            "title": "Nmap scan timed out",
            "category": "network",
            "source": "nmap",
            "port": 0, "protocol": "tcp", "service": "nmap", "state": "error",
            "cve_id": None, "cvss_score": 0.0, "severity": "info", "confidence": 0.0,
            "evidence": "Nmap scan exceeded the 10-minute timeout.",
            "remediation": "Reduce the port range or use a faster timing template.",
            "compliance_map": [], "metadata": {**metadata, "scanner": "nmap"},
        }], metadata
    except Exception as exc:
        return [{
            "title": f"Nmap scan failed: {exc}",
            "category": "network",
            "source": "nmap",
            "port": 0, "protocol": "tcp", "service": "nmap", "state": "error",
            "cve_id": None, "cvss_score": 0.0, "severity": "info", "confidence": 0.0,
            "evidence": str(exc),
            "remediation": "Check Nmap binary, permissions, and target connectivity.",
            "compliance_map": [], "metadata": {**metadata, "scanner": "nmap"},
        }], metadata
