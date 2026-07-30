from __future__ import annotations

from urllib.parse import quote


OS_BENCHMARKS = {
    "windows": "CIS Microsoft Windows Server Benchmark",
    "linux": "CIS Linux Benchmark",
    "ubuntu": "CIS Ubuntu Linux Benchmark",
    "debian": "CIS Debian Linux Benchmark",
    "rhel": "CIS Red Hat Enterprise Linux Benchmark",
    "centos": "CIS Red Hat Enterprise Linux Benchmark",
    "rocky": "CIS Red Hat Enterprise Linux Benchmark",
    "almalinux": "CIS Red Hat Enterprise Linux Benchmark",
    "macos": "CIS Apple macOS Benchmark",
    "network_device": "CIS Network Device Benchmark",
    "server": "CIS Server Benchmark",
    "network": "CIS Controls v8",
    "web": "CIS Apache / NGINX / IIS Benchmarks",
    "database": "CIS Database Server Benchmarks",
    "container": "CIS Docker Benchmark",
}


SERVICE_VENDOR_LINKS = {
    "apache": "https://httpd.apache.org/security/vulnerabilities_24.html",
    "nginx": "https://nginx.org/en/security_advisories.html",
    "iis": "https://learn.microsoft.com/en-us/iis/manage/configuring-security/",
    "ssh": "https://www.ssh.com/academy/ssh/sshd_config",
    "redis": "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
    "docker": "https://docs.docker.com/engine/security/",
    "elasticsearch": "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-settings.html",
    "postgresql": "https://www.postgresql.org/docs/current/security.html",
    "mysql": "https://dev.mysql.com/doc/refman/8.0/en/security.html",
    "mssql": "https://learn.microsoft.com/en-us/sql/relational-databases/security/security-center-for-sql-server-database-engine-and-azure-sql-database",
    "oracle": "https://www.oracle.com/security-alerts/",
    "kibana": "https://www.elastic.co/guide/en/kibana/current/xpack-security.html",
    "webmin": "https://webmin.com/security/",
    "ftp": "https://www.cisa.gov/news-events/cybersecurity-advisories",
    "telnet": "https://www.cisa.gov/news-events/cybersecurity-advisories",
    "smb": "https://learn.microsoft.com/en-us/windows-server/storage/file-server/file-server-smb-overview",
    "rdp": "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/security/",
    "http": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
    "https": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
}


def infer_os_family(*, service: str = "", banner: str = "", port: int = 0, title: str = "", evidence: str = "") -> str:
    text = " ".join([service, banner, title, evidence]).lower()
    if any(token in text for token in ["mac os", "macos", "darwin", "os x"]):
        return "macos"
    if any(token in text for token in ["microsoft-iis", "windows", "rdp", "smb", "microsoft"]):
        return "windows"
    if any(token in text for token in ["ubuntu"]):
        return "ubuntu"
    if any(token in text for token in ["debian"]):
        return "debian"
    if any(token in text for token in ["red hat", "rhel"]):
        return "rhel"
    if any(token in text for token in ["centos"]):
        return "centos"
    if any(token in text for token in ["rocky linux"]):
        return "rocky"
    if any(token in text for token in ["alma", "almalinux"]):
        return "almalinux"
    if any(token in text for token in ["nginx", "apache", "openssh", "linux", "systemd"]):
        return "linux"
    if service in {"docker"} or port in {2375, 2376}:
        return "container"
    if any(token in text for token in ["cisco", "router", "switch", "fortinet", "fortigate", "juniper", "palo alto", "mikrotik", "vyos", "sonicwall"]):
        return "network_device"
    if service in {"postgresql", "mysql", "mssql", "oracle", "mongodb", "redis", "elasticsearch"}:
        return "database"
    if service in {"apache", "nginx", "iis", "http", "https"} or port in {80, 443, 8080, 8443}:
        return "web"
    if any(token in text for token in ["server", "vmware", "hyper-v", "esxi"]):
        return "server"
    return "network"


def benchmark_for_os(os_family: str) -> str:
    return OS_BENCHMARKS.get(os_family, "CIS Controls v8")


def compliance_tags(*, os_family: str, service: str = "", extra: list[str] | None = None) -> list[str]:
    tags = ["NIST RA-5", "OWASP ASVS V1", "CIS Controls 7", benchmark_for_os(os_family)]
    if service in {"apache", "nginx", "iis", "http", "https"}:
        tags.append("OWASP ASVS V1")
        tags.append("CIS Web Server Benchmark")
    if service in {"postgresql", "mysql", "mssql", "oracle", "redis", "mongodb", "elasticsearch"}:
        tags.append("CIS Database Benchmark")
    if service == "docker":
        tags.append("CIS Docker Benchmark")
    if extra:
        tags.extend(extra)
    return list(dict.fromkeys(tags))


def recommendation_for_finding(*, title: str, service: str = "", os_family: str = "network") -> str:
    title_lower = title.lower()
    benchmark = benchmark_for_os(os_family)
    if "legacy tls" in title_lower or "weak tls" in title_lower or "hsts" in title_lower:
        return f"Apply {benchmark} TLS hardening guidance, disable weak protocol/cipher support, and verify modern HTTPS header coverage."
    if "content-security-policy" in title_lower or "clickjacking" in title_lower or "mime sniffing" in title_lower:
        return "Apply OWASP and CIS web-hardening controls for security headers, framing restrictions, and browser content protections."
    if "redis" in title_lower:
        return f"Follow {benchmark} and Redis vendor hardening guidance: require authentication, restrict bind addresses, and isolate administrative access."
    if "docker" in title_lower:
        return "Apply the CIS Docker Benchmark: disable unauthenticated TCP exposure, require TLS, and limit daemon access to trusted operators."
    if service in {"postgresql", "mysql", "mssql", "oracle", "redis", "mongodb", "elasticsearch"}:
        return f"Apply {benchmark}, restrict administrative exposure, enforce authentication, patch the service, and validate network segmentation."
    if service in {"ssh", "rdp", "smb", "ftp", "telnet"}:
        return f"Apply {benchmark}, limit management protocol exposure, disable legacy services where possible, and restrict access to trusted management networks."
    return f"Review the host against {benchmark}, reduce unnecessary exposure, patch the affected software, and validate the hardened configuration with a re-scan."


def vendor_reference_links(*, cve_id: str | None = None, service: str = "", title: str = "") -> list[str]:
    links: list[str] = []
    if cve_id:
        links.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        links.append(f"https://www.cve.org/CVERecord?id={quote(cve_id)}")
    service_key = (service or "").lower()
    if service_key in SERVICE_VENDOR_LINKS:
        links.append(SERVICE_VENDOR_LINKS[service_key])
    title_lower = title.lower()
    if "content-security-policy" in title_lower or "clickjacking" in title_lower or "mime sniffing" in title_lower:
        links.append("https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html")
    if "tls" in title_lower or "certificate" in title_lower:
        links.append("https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")
    links.append("https://www.cisecurity.org/cis-benchmarks")
    return list(dict.fromkeys(links))
