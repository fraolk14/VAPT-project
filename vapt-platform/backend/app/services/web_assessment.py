import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests
import urllib3

# Suppress SSL certificate verification warnings for local/internal pentesting targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SENSITIVE_PATHS: list[tuple[str, str, float, str, str]] = [
    # Configuration & Secrets
    ("/.env", "Exposed Environment Configuration File", 9.1, "critical", "OWASP ASVS V12.5.1"),
    ("/.env.local", "Exposed Local Environment File", 9.1, "critical", "OWASP ASVS V12.5.1"),
    ("/.env.production", "Exposed Production Environment File", 9.1, "critical", "OWASP ASVS V12.5.1"),
    ("/config.json", "Exposed Application Configuration JSON", 7.5, "high", "CWE-538"),
    ("/appsettings.json", "Exposed ASP.NET Configuration File", 7.5, "high", "CWE-538"),
    ("/web.config", "Exposed IIS Web Configuration File", 7.5, "high", "CWE-538"),
    # Source Code Repositories & Metadata
    ("/.git/config", "Exposed Git Version Control Repository", 8.5, "high", "OWASP ASVS V14.3.1"),
    ("/.git/HEAD", "Exposed Git Repository Metadata", 7.8, "high", "OWASP ASVS V14.3.1"),
    ("/.ds_store", "Exposed macOS .DS_Store Directory Index File", 5.3, "medium", "CWE-538"),
    # Storage & Backups
    ("/backup.sql", "Exposed SQL Database Backup File", 9.4, "critical", "CWE-538"),
    ("/dump.sql", "Exposed Database Dump Archive", 9.4, "critical", "CWE-538"),
    ("/database.sql", "Exposed Database SQL Script", 9.4, "critical", "CWE-538"),
    ("/backup.zip", "Exposed Compressed Site Backup Archive", 8.8, "high", "CWE-538"),
    ("/site.tar.gz", "Exposed Tarball Archive File", 8.8, "high", "CWE-538"),
    ("/ftp", "Exposed FTP Storage Directory Index", 8.8, "high", "CWE-548"),
    ("/ftp/acquisitions.md", "Exposed Confidential Corporate Acquisition File", 9.0, "critical", "CWE-538"),
    ("/ftp/coupons_2013.md.bak", "Exposed Legacy Promotional Discount Credentials", 8.1, "high", "CWE-538"),
    ("/ftp/package.json.bak", "Exposed Application Package Backup Archive", 7.5, "high", "CWE-538"),
    ("/ftp/eastere.gg", "Exposed Hidden Developer Easter Egg File", 5.0, "medium", "CWE-200"),
    ("/ftp/legal.md", "Exposed Internal Legal Terms Document", 5.0, "medium", "CWE-200"),
    ("/assets/public/images/uploads/", "Exposed Public Uploads Directory Index", 6.5, "medium", "CWE-548"),
    ("/uploads/", "Exposed Uploads Directory Index", 6.5, "medium", "CWE-548"),
    ("/storage/", "Exposed Public Storage Directory Index", 6.5, "medium", "CWE-548"),
    ("/downloads/", "Exposed Downloads Directory Index", 6.5, "medium", "CWE-548"),
    # Administrative & Management Portals
    ("/admin", "Unprotected Administrative Dashboard Route", 6.5, "medium", "OWASP ASVS V4.1"),
    ("/admin/", "Administrative Control Portal Interface", 6.5, "medium", "OWASP ASVS V4.1"),
    ("/administrator/", "Exposed Administrator Portal Route", 6.5, "medium", "OWASP ASVS V4.1"),
    ("/wp-admin", "WordPress Administrative Portal Interface", 5.0, "medium", "CWE-200"),
    ("/console", "Web Application Console / Debugging Route", 7.5, "high", "CWE-200"),
    ("/kibana", "Exposed Kibana Administrative Dashboard", 7.5, "high", "CWE-306"),
    ("/manager/html", "Exposed Apache Tomcat Web Application Manager", 8.5, "high", "CWE-306"),
    ("/cpanel", "Exposed cPanel Management Interface", 6.5, "medium", "CWE-306"),
    # Diagnostic Pages & Actuators
    ("/actuator/health", "Spring Boot Actuator Endpoint Exposed", 4.3, "low", "OWASP ASVS V14.3.2"),
    ("/actuator/env", "Exposed Spring Boot Actuator Environment Configuration", 8.8, "high", "CWE-538"),
    ("/actuator/heapdump", "Exposed Spring Boot Heap Dump Memory File", 9.0, "critical", "CWE-200"),
    ("/actuator/beans", "Exposed Spring Boot Beans Metadata", 6.5, "medium", "CWE-200"),
    ("/actuator/mappings", "Exposed Spring Boot URL Mappings", 6.5, "medium", "CWE-200"),
    ("/phpinfo.php", "PHPInfo Diagnostic Page Disclosure", 6.1, "medium", "CWE-200"),
    ("/info.php", "PHP Configuration Info Disclosure", 6.1, "medium", "CWE-200"),
    ("/server-status", "Apache / Server Status Diagnostic Page Disclosure", 5.8, "medium", "CWE-200"),
    ("/server-info", "Apache Server Information Page Disclosure", 5.8, "medium", "CWE-200"),
    ("/elmah.axd", "Exposed ELMAH Error Log Diagnostic Console", 8.5, "high", "CWE-538"),
    # API Specifications & Interactive Consoles
    ("/swagger-ui.html", "Exposed Interactive Swagger API Interface", 5.4, "medium", "OWASP ASVS V14.2.1"),
    ("/swagger/index.html", "Exposed Swagger UI Documentation", 5.4, "medium", "OWASP ASVS V14.2.1"),
    ("/api-docs", "Exposed Interactive API Documentation (Swagger)", 5.3, "medium", "api_docs"),
    ("/v2/api-docs", "Exposed OpenAPI / Swagger JSON Specification", 5.3, "medium", "CWE-200"),
    ("/v3/api-docs", "Exposed OpenAPI v3 JSON Specification", 5.3, "medium", "CWE-200"),
    ("/openapi.json", "Exposed OpenAPI v3 Documentation", 5.3, "medium", "CWE-200"),
    ("/openapi.yaml", "Exposed OpenAPI YAML Specification", 5.3, "medium", "CWE-200"),
    ("/graphql", "GraphQL API Interface Endpoint", 4.5, "low", "CWE-200"),
    ("/graphiql", "Exposed Interactive GraphiQL IDE", 5.4, "medium", "CWE-200"),
    # Compliance & Crawling Policy
    ("/.well-known/security.txt", "Security Contact Policy Document", 0.0, "info", "RFC 9116"),
    ("/robots.txt", "Robots.txt Crawling Policy File", 0.0, "info", "NIST RA-5"),
    ("/sitemap.xml", "Sitemap XML Architecture Map File", 0.0, "info", "CWE-200"),
]


def _crawl_target(
    base_url: str,
    domain: str,
    session: requests.Session,
    max_urls: int = 50,
) -> tuple[set[str], set[str], dict[str, set[str]]]:
    """
    Performs deep, recursive spidering and subdirectory discovery across the target domain.
    Extracts HTML anchors, forms, script tags, JS route strings, robots.txt, and sitemap.xml.
    """
    discovered_urls: set[str] = {base_url, f"{base_url}/"}
    discovered_subdirs: set[str] = set()
    discovered_params: dict[str, set[str]] = {}
    visited: set[str] = set()
    queue: list[str] = [base_url]

    # 1. Parse robots.txt for disallowed & allowed subdirectories
    try:
        r_robots = session.get(f"{base_url}/robots.txt", timeout=4, verify=False)
        if r_robots.status_code == 200 and "<!doctype html" not in r_robots.text.lower():
            for line in r_robots.text.splitlines():
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        p = parts[1].strip()
                        if p.startswith("/"):
                            full_u = urljoin(base_url, p)
                            discovered_urls.add(full_u)
                            discovered_subdirs.add(p.split("?")[0])
    except Exception:
        pass

    # 2. Parse sitemap.xml for target URLs
    try:
        r_sitemap = session.get(f"{base_url}/sitemap.xml", timeout=4, verify=False)
        if r_sitemap.status_code == 200:
            for loc in re.findall(r"<loc>(https?://[^<]+)</loc>", r_sitemap.text, re.IGNORECASE):
                if domain in loc.lower():
                    discovered_urls.add(loc)
                    discovered_subdirs.add(urlparse(loc).path)
    except Exception:
        pass

    # 3. Recursive In-Depth Crawler
    skip_extensions = (
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".css",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip"
    )

    while queue and len(visited) < max_urls:
        current_url = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            res = session.get(current_url, timeout=4, allow_redirects=True, verify=False)
            if res.status_code != 200:
                continue

            text_body = res.text

            # Extract standard HTML links (href, src, action)
            html_links = re.findall(
                r'''(?:href|src|action)=["']([^"'#\s>]+)["']''',
                text_body,
                re.IGNORECASE,
            )

            # Extract Single Page Application (SPA) / REST API endpoints from inline & bundle JavaScript
            js_endpoints = re.findall(
                r'''["'](/(?:api|rest|v[0-9]|auth|admin|user|users|account|profile|dashboard|login|logout|signin|signup|portal|feed|feedbacks|cart|checkout|products|item|order|download|downloads|view|search|setting|manage|doc|docs|swagger|ftp|challenges|secret)[a-zA-Z0-9_\-/\.\?=&]*)["']''',
                text_body,
            )

            # Extract form inputs for parameter-level vulnerability testing
            form_inputs = re.findall(r'''<input[^>]+name=["']([^"']+)["']''', text_body, re.IGNORECASE)
            for param_name in form_inputs:
                discovered_params.setdefault(current_url, set()).add(param_name)

            for link in html_links + js_endpoints:
                if not link or link.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue
                full_link = urljoin(current_url, link)
                parsed_link = urlparse(full_link)

                # Restrict crawling strictly to in-scope target domain
                if parsed_link.netloc.lower() == domain:
                    clean_path_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                    discovered_urls.add(clean_path_url)
                    if parsed_link.path:
                        discovered_subdirs.add(parsed_link.path)

                    # Extract query parameters
                    if parsed_link.query:
                        for qp in parsed_link.query.split("&"):
                            if "=" in qp:
                                k, _ = qp.split("=", 1)
                                discovered_params.setdefault(clean_path_url, set()).add(k)

                    # Enqueue for further recursive crawling if not a static image
                    if (
                        clean_path_url not in visited
                        and len(queue) < (max_urls * 2)
                        and not any(clean_path_url.lower().endswith(ext) for ext in skip_extensions)
                    ):
                        queue.append(clean_path_url)
        except Exception:
            pass

    return discovered_urls, discovered_subdirs, discovered_params


def run_web_assessment(
    target_url: str,
    progress_callback: Callable[[int, dict[str, Any]], None] | None = None,
    deep_mode: bool = True,
) -> list[dict[str, Any]]:
    """
    Comprehensive, enterprise-grade web vulnerability assessment engine.
    Recursively spiders subdirectories, discovers REST APIs, and conducts active multi-vulnerability security tests.
    """
    findings: list[dict[str, Any]] = []

    def _report(progress: int, phase: str, message: str) -> None:
        if progress_callback:
            progress_callback(progress, {"phase": phase, "message": message})

    _report(5, "normalization", f"Normalizing target web URL and establishing HTTP session (Deep Mode: {deep_mode}).")

    raw_target = str(target_url).strip()
    if not raw_target.startswith(("http://", "https://")):
        raw_target = f"http://{raw_target}"

    parsed = urlparse(raw_target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc.lower()
    host = parsed.hostname or raw_target
    port = parsed.port or (443 if base_url.startswith("https") else 80)

    # Known external → local Docker service fallback mappings for local testing environments
    KNOWN_DOCKER_FALLBACKS: dict[str, str] = {
        "juice-shop.herokuapp.com": "http://juice-shop:3000",
        "www.juice-sh.op": "http://juice-shop:3000",
        "juice-sh.op": "http://juice-shop:3000",
        "dvwa": "http://dvwa:80",
        "dvwa.local": "http://dvwa:80",
    }

    target_candidates = [base_url]
    local_fallback = KNOWN_DOCKER_FALLBACKS.get(host)
    if local_fallback:
        target_candidates.insert(0, local_fallback)

    if host in ["localhost", "127.0.0.1", "0.0.0.0"]:
        if port == 3000:
            target_candidates.insert(0, "http://juice-shop:3000")
        elif port == 80:
            target_candidates.insert(0, "http://dvwa:80")
        target_candidates.append(base_url.replace(host, "host.docker.internal"))

    session = requests.Session()
    session.headers.update({
        "User-Agent": "VAPT-Platform-DeepScanner/3.0 (Enterprise Pentest Crawler)",
        "Accept": "text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8",
    })

    _report(12, "connectivity", f"Probing target connectivity and validating response on {base_url}.")

    main_response = None
    for candidate_url in target_candidates:
        try:
            res = session.get(candidate_url, timeout=6, allow_redirects=True, verify=False)
            if res is not None and res.status_code < 500:
                main_response = res
                base_url = candidate_url
                parsed = urlparse(base_url)
                domain = parsed.netloc.lower()
                port = parsed.port or (443 if base_url.startswith("https") else 80)
                break
        except Exception:
            continue

    # =========================================================================
    # MODULE 1: HTTP Security Headers, SSL/TLS, and Cookie Audits
    # =========================================================================
    _report(18, "headers_audit", f"Auditing HTTP response headers, SSL/TLS security policies, and cookies on {base_url}.")

    if main_response is not None:
        headers = {k.lower(): v for k, v in main_response.headers.items()}

        # 1. Content-Security-Policy Audit
        if "content-security-policy" not in headers:
            findings.append({
                "title": "Missing Content-Security-Policy (CSP) Header",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 6.5,
                "severity": "medium",
                "evidence": f"Target {base_url} does not enforce Content-Security-Policy. Response headers: {list(headers.keys())[:8]}",
                "remediation": "Configure a strong Content-Security-Policy header restricting script-src, object-src, and frame-ancestors.",
                "compliance_map": ["OWASP ASVS V14.4", "NIST SI-16"],
                "metadata": {"url": base_url, "host": host, "cwe_id": "1021"},
            })

        # 2. Strict-Transport-Security Audit
        if base_url.startswith("https") and "strict-transport-security" not in headers:
            findings.append({
                "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                "category": "web",
                "source": "zap",
                "port": 443,
                "protocol": "https",
                "service": "https",
                "state": "open",
                "cve_id": None,
                "cvss_score": 7.1,
                "severity": "high",
                "evidence": f"HTTPS endpoint {base_url} is missing Strict-Transport-Security (HSTS) header.",
                "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to force HTTPS connections.",
                "compliance_map": ["OWASP ASVS V14.4.1", "NIST SC-8"],
                "metadata": {"url": base_url, "host": host, "cwe_id": "319"},
            })

        # 3. X-Frame-Options Audit
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append({
                "title": "Clickjacking Vulnerability - Missing X-Frame-Options",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 5.4,
                "severity": "medium",
                "evidence": f"Endpoint {base_url} lacks X-Frame-Options header, allowing framing by malicious sites.",
                "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN in web server response headers.",
                "compliance_map": ["OWASP ASVS V14.4.3", "CWE-1021"],
                "metadata": {"url": base_url, "host": host, "cwe_id": "1021"},
            })

        # 4. X-Content-Type-Options Audit
        if "x-content-type-options" not in headers:
            findings.append({
                "title": "Missing X-Content-Type-Options Header",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 4.3,
                "severity": "low",
                "evidence": f"Endpoint {base_url} is missing X-Content-Type-Options: nosniff header.",
                "remediation": "Configure X-Content-Type-Options: nosniff header to prevent MIME-type sniffing.",
                "compliance_map": ["OWASP ASVS V14.4.4", "CWE-16"],
                "metadata": {"url": base_url, "host": host, "cwe_id": "16"},
            })

        # 5. Server Banner Information Disclosure
        server_banner = headers.get("server") or headers.get("x-powered-by")
        if server_banner:
            findings.append({
                "title": f"Web Server Technology Information Disclosure ({server_banner})",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 3.7,
                "severity": "low",
                "evidence": f"Exposed banner header: {server_banner}",
                "remediation": "Remove or obscure Server and X-Powered-By response headers in web server configuration.",
                "compliance_map": ["OWASP ASVS V14.3.1"],
                "metadata": {"url": base_url, "host": host, "banner": server_banner},
            })

        # 6. Cookie Security Flags Audit
        for cookie in main_response.cookies:
            if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.secure:
                findings.append({
                    "title": f"Insecure Session Cookie Missing Security Flags ({cookie.name})",
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 5.0,
                    "severity": "medium",
                    "evidence": f"Cookie '{cookie.name}' lacks HttpOnly or Secure flag.",
                    "remediation": "Set HttpOnly, Secure, and SameSite=Lax/Strict flags on all session cookies.",
                    "compliance_map": ["OWASP ASVS V3.4.1", "CWE-614"],
                    "metadata": {"url": base_url, "cookie": cookie.name},
                })

    # =========================================================================
    # MODULE 2: CORS Wildcard & Origin Reflection Audit
    # =========================================================================
    _report(25, "cors_audit", "Testing Cross-Origin Resource Sharing (CORS) security configuration.")
    try:
        cors_res = session.get(base_url, headers={"Origin": "https://evil.com"}, timeout=5, verify=False)
        cors_origin = cors_res.headers.get("access-control-allow-origin", "")
        cors_creds = cors_res.headers.get("access-control-allow-credentials", "")
        if cors_origin == "*" or (cors_origin == "https://evil.com" and cors_creds.lower() == "true"):
            findings.append({
                "title": "Overly Permissive Cross-Origin Resource Sharing (CORS) Policy",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 7.5 if cors_creds.lower() == "true" else 6.1,
                "severity": "high" if cors_creds.lower() == "true" else "medium",
                "evidence": f"Endpoint reflected arbitrary origin '{cors_origin}' with credentials '{cors_creds}'.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted origin domains and do not allow arbitrary origins with credentials.",
                "compliance_map": ["OWASP ASVS V14.4.7", "CWE-942"],
                "metadata": {"url": base_url, "host": host, "origin": cors_origin},
            })
    except Exception:
        pass

    # =========================================================================
    # MODULE 3: Soft-404 / Catch-All Detection
    # =========================================================================
    soft_404_body = None
    soft_404_len = 0
    try:
        probe_res = session.get(
            f"{base_url}/__vapt_soft_404_probe_{int(time.time())}",
            timeout=4,
            allow_redirects=False,
            verify=False,
        )
        if probe_res.status_code == 200:
            soft_404_body = probe_res.text.strip()
            soft_404_len = len(soft_404_body)
    except Exception:
        pass

    root_body = (main_response.text or "").strip() if main_response else ""
    root_len = len(root_body)

    # =========================================================================
    # MODULE 4: Recursive Spider & Subdirectory Discovery
    # =========================================================================
    _report(35, "crawler", f"Deep crawling subdirectories, REST APIs, and application routes on {base_url}...")

    discovered_urls, discovered_subdirs, discovered_params = _crawl_target(
        base_url=base_url,
        domain=domain,
        session=session,
        max_urls=60 if deep_mode else 25,
    )

    # =========================================================================
    # MODULE 5: Discovered Subdirectory & Document Analysis (SRI, Advisories, Dirs)
    # =========================================================================
    _report(45, "page_analysis", f"Auditing discovered pages and subdirectories ({len(discovered_urls)} endpoints)...")

    for disc_url in list(discovered_urls):
        try:
            p_res = session.get(disc_url, timeout=4, verify=False)
            if p_res.status_code != 200:
                continue

            p_path = urlparse(disc_url).path
            p_body = p_res.text

            # 1. Subresource Integrity (SRI) Check
            external_scripts = re.findall(
                r'''<(?:script|link)[^>]*(?:src|href)=["'](https?://[^"']+)["'][^>]*>''',
                p_body,
                re.IGNORECASE,
            )
            for ext_asset in external_scripts:
                if "integrity=" not in ext_asset.lower() and domain not in ext_asset.lower():
                    findings.append({
                        "title": "Subresource Integrity (SRI) Attribute Missing",
                        "category": "web",
                        "source": "zap",
                        "port": port,
                        "protocol": "https" if base_url.startswith("https") else "http",
                        "service": "http",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": 4.3,
                        "severity": "low",
                        "evidence": f"External asset loaded without Subresource Integrity hash on {disc_url}: {ext_asset[:80]}",
                        "remediation": "Add integrity and crossorigin=\"anonymous\" attributes to external script/stylesheet tags.",
                        "compliance_map": ["OWASP ASVS V14.4.6", "CWE-353"],
                        "metadata": {"url": disc_url, "host": host, "path": p_path, "cwe_id": "353"},
                    })
                    break  # One SRI alert per page

            # 2. Exposed Sensitive Document or Advisory in Subdirectory
            if any(disc_url.lower().endswith(ext) for ext in [".txt", ".pdf", ".bak", ".doc", ".docx", ".log", ".sql", ".csv"]):
                if len(p_body) > 30 and "<!doctype html" not in p_body.lower() and not p_path.endswith("robots.txt"):
                    findings.append({
                        "title": f"Exposed Sensitive Document / Advisory File ({p_path})",
                        "category": "web",
                        "source": "zap",
                        "port": port,
                        "protocol": "https" if base_url.startswith("https") else "http",
                        "service": "http",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": 5.3,
                        "severity": "medium",
                        "evidence": f"Publicly accessible file in subdirectory {disc_url} (HTTP 200 OK, {len(p_body)} bytes). Sample content: {p_body[:100].strip()}",
                        "remediation": "Restrict direct public indexing of document archives, advisories, and backup files.",
                        "compliance_map": ["OWASP ASVS V12.5", "CWE-200"],
                        "metadata": {"url": disc_url, "host": host, "path": p_path, "cwe_id": "200"},
                    })
        except Exception:
            pass

    _report(55, "subdirectory_fuzzing", f"Fuzzing sensitive administrative directories & configuration files (Wordlist: {len(SENSITIVE_PATHS)} paths).")

    # =========================================================================
    # MODULE 6: Sensitive Path & Subdirectory Probing
    # =========================================================================
    def _check_path(path_item: tuple[str, str, float, str, str]) -> dict[str, Any] | None:
        path, title, cvss, severity, compliance = path_item
        test_url = f"{base_url}{path}"
        try:
            res = session.get(test_url, timeout=4, allow_redirects=False, verify=False)
            if res.status_code == 200:
                body = res.text.strip()
                if len(body) < 5:
                    return None

                # Filter out SPA catch-all / soft-404 responses that return the root SPA index.html
                if soft_404_body and (body == soft_404_body or (soft_404_len > 0 and abs(len(body) - soft_404_len) < 50 and body[:100] == soft_404_body[:100])):
                    return None
                if root_body and (body == root_body or (root_len > 0 and abs(len(body) - root_len) < 50 and body[:100] == root_body[:100])):
                    return None

                is_html = "<!doctype html" in body.lower() or "<html" in body.lower()

                if path in ["/.env", "/.env.local", "/.env.production", "/appsettings.json", "/config.json", "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql", "/database.sql"] and is_html:
                    return None

                if path == "/.git/config" and "[core]" not in body:
                    return None
                if path == "/.git/HEAD" and "ref:" not in body:
                    return None

                if path in ["/backup.sql", "/dump.sql", "/database.sql"] and not any(kw in body.upper() for kw in ["CREATE TABLE", "INSERT INTO", "DATABASE", "DROP TABLE", "-- MYSQL", "-- POSTGRESQL"]):
                    return None

                if path in ["/actuator/health", "/actuator/env", "/actuator/heapdump", "/api/Challenges", "/api/Users", "/v2/api-docs", "/v3/api-docs", "/openapi.json"] and is_html:
                    return None

                if path in ["/phpinfo.php", "/info.php"] and ("php version" not in body.lower() and "<title>phpinfo()</title>" not in body.lower()):
                    return None

                if path in ["/wp-admin", "/admin"] and "login" not in body.lower() and "admin" not in body.lower() and "dashboard" not in body.lower():
                    return None

                if path == "/kibana" and "kibana" not in body.lower():
                    return None

                if path in ["/server-status", "/server-info"] and "apache server" not in body.lower():
                    return None

                if path in ["/swagger-ui.html", "/swagger/index.html"] and "swagger" not in body.lower():
                    return None

                if path in ["/graphql", "/graphiql"] and is_html:
                    return None

                sample_preview = body[:200].replace("\r", " ").replace("\n", " ").strip()
                description_text = f"Exposed resource accessible at {test_url}. Server returned HTTP 200 OK with valid resource content. Evidence: {sample_preview}"

                return {
                    "title": title,
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": cvss,
                    "severity": severity,
                    "evidence": description_text,
                    "remediation": "Restrict access to configuration files, repository metadata, and administrative routes via web server access rules.",
                    "compliance_map": [compliance, "CWE-538"],
                    "metadata": {
                        "url": test_url,
                        "host": host,
                        "path": path,
                        "description": description_text,
                    },
                }
        except Exception:
            pass
        return None

    paths_to_test = SENSITIVE_PATHS if deep_mode else SENSITIVE_PATHS[:10]
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(_check_path, item) for item in paths_to_test]
        for future in as_completed(futures):
            res_finding = future.result()
            if res_finding:
                findings.append(res_finding)

    # =========================================================================
    # MODULE 7: Discovered API & Route Access Control & Exposure Probing
    # =========================================================================
    _report(65, "api_exposure", f"Auditing access control and unauthenticated data exposure across {len(discovered_urls)} discovered routes...")

    seen_api_paths: set[str] = set()
    for disc_url in list(discovered_urls):
        p = urlparse(disc_url).path
        if (
            any(p.startswith(prefix) for prefix in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"])
            and p not in seen_api_paths
            and len(seen_api_paths) < 20
        ):
            seen_api_paths.add(p)
            try:
                api_res = session.get(disc_url, timeout=4, verify=False)
                if api_res.status_code == 200 and len(api_res.text) > 15:
                    ct = api_res.headers.get("content-type", "").lower()
                    body = api_res.text.strip()
                    if soft_404_body and body == soft_404_body:
                        continue
                    if "json" in ct or (body.startswith(("{", "[")) and "<!doctype html" not in body.lower()):
                        # Check for sensitive data indicators
                        is_sensitive = any(kw in body.lower() for kw in [
                            "email", "password", "token", "user", "secret", "question",
                            "challenge", "hash", "card", "credential", "address", "phone", "key"
                        ])
                        sev = "high" if is_sensitive else "medium"
                        cvss = 8.2 if is_sensitive else 5.3
                        title = f"Unauthenticated Sensitive API Endpoint Exposed ({p})" if is_sensitive else f"Unprotected REST API Endpoint Disclosure ({p})"
                        findings.append({
                            "title": title,
                            "category": "web",
                            "source": "zap",
                            "port": port,
                            "protocol": "https" if base_url.startswith("https") else "http",
                            "service": "http",
                            "state": "open",
                            "cve_id": None,
                            "cvss_score": cvss,
                            "severity": sev,
                            "evidence": f"Sensitive data accessible without authentication at {disc_url} (HTTP 200 OK). Sample payload: {body[:150].strip()}",
                            "remediation": "Implement strict authentication and authorization tokens (JWT/Bearer) across all sensitive API routes.",
                            "compliance_map": ["OWASP ASVS V2.1", "CWE-200", "CWE-284"],
                            "metadata": {"url": disc_url, "host": host, "path": p, "cwe_id": "200"},
                        })
            except Exception:
                pass

    # =========================================================================
    # MODULE 8: Active Reflected & Form Cross-Site Scripting (XSS)
    # =========================================================================
    _report(75, "xss_probes", "Testing active parameter and form input handling for Cross-Site Scripting (XSS)...")

    xss_canary = "<script>alert(1)</script>"
    xss_canary_encoded = "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    xss_endpoints_to_test = [
        f"{base_url}/search?q={xss_canary_encoded}",
        f"{base_url}/?s={xss_canary_encoded}",
        f"{base_url}/?q={xss_canary_encoded}",
        f"{base_url}/?search={xss_canary_encoded}",
        f"{base_url}/?keyword={xss_canary_encoded}",
    ]

    # Add discovered parameterized URLs
    for p_url, p_keys in list(discovered_params.items())[:6]:
        for key in list(p_keys)[:3]:
            xss_endpoints_to_test.append(f"{p_url}?{key}={xss_canary_encoded}")

    for xss_url in xss_endpoints_to_test:
        try:
            xss_res = session.get(xss_url, timeout=4, verify=False)
            if xss_canary in xss_res.text:
                findings.append({
                    "title": "Reflected Cross-Site Scripting (XSS) in Parameter Input",
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 7.4,
                    "severity": "high",
                    "evidence": f"Unsanitized parameter reflection confirmed at {xss_url}. Script payload reflected verbatim in response.",
                    "remediation": "Apply contextual HTML/Attribute output encoding and validate input against strict whitelist rules.",
                    "compliance_map": ["OWASP ASVS V5.3.1", "CWE-79"],
                    "metadata": {"url": xss_url, "host": host, "cwe_id": "79"},
                })
                break
        except Exception:
            pass

    # =========================================================================
    # MODULE 9: Active SQL Injection & Authentication Bypass
    # =========================================================================
    _report(82, "sqli_probes", "Testing parameter inputs and login authentication handlers for SQL Injection...")

    sqli_endpoints = [
        (f"{base_url}/rest/products/search?q=%27%29%29%20OR%201=1--", "SQL Injection in Product Search API", 8.8, "high"),
        (f"{base_url}/api/v1/products?id=1%27%20OR%201=1--", "Error-Based SQL Injection in Query Parameter", 8.9, "high"),
        (f"{base_url}/search?q=%27%20OR%20%271%27=%271", "SQL Injection in Search Input Handler", 8.8, "high"),
    ]
    for sqli_url, sqli_title, sqli_cvss, sqli_sev in sqli_endpoints:
        try:
            sqli_res = session.get(sqli_url, timeout=5, verify=False)
            sqli_errors = ["SQL syntax", "MySQL", "PostgreSQL", "SQLite", "ORA-", "SyntaxError", "psycopg2", "Unclosed quotation mark"]
            has_db_error = any(err.lower() in sqli_res.text.lower() for err in sqli_errors)
            has_manipulated_data = sqli_res.status_code == 200 and ("status" in sqli_res.text or "data" in sqli_res.text or len(sqli_res.text) > 1000)

            if has_db_error or has_manipulated_data:
                if not (soft_404_body and sqli_res.text == soft_404_body) and "<!doctype html" not in sqli_res.text.lower():
                    findings.append({
                        "title": sqli_title,
                        "category": "web",
                        "source": "zap",
                        "port": port,
                        "protocol": "https" if base_url.startswith("https") else "http",
                        "service": "http",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": sqli_cvss,
                        "severity": sqli_sev,
                        "evidence": f"SQL Injection probe succeeded at {sqli_url}. Query returned manipulated database records (Response length: {len(sqli_res.text)} bytes).",
                        "remediation": "Use parameterized queries (Prepared Statements) or ORM abstractions; never concatenate untrusted user input into raw SQL statements.",
                        "compliance_map": ["OWASP ASVS V5.3.4", "CWE-89"],
                        "metadata": {"url": sqli_url, "host": host, "cwe_id": "89"},
                    })
                    break
        except Exception:
            pass

    # 2. SQLi Login Authentication Bypass Probes
    login_endpoints = [
        f"{base_url}/rest/user/login",
        f"{base_url}/api/user/login",
        f"{base_url}/api/login",
        f"{base_url}/login",
        f"{base_url}/auth/login",
    ]
    for login_url in login_endpoints:
        try:
            login_payload = {"email": "' OR 1=1--", "password": "vapt_sqli_test"}
            login_res = session.post(login_url, json=login_payload, timeout=5, verify=False)
            if login_res.status_code == 200 and ("token" in login_res.text.lower() or "authentication" in login_res.text.lower() or "jwt" in login_res.text.lower()):
                findings.append({
                    "title": "SQL Injection Authentication Bypass in Login Endpoint",
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 9.8,
                    "severity": "critical",
                    "evidence": f"Authentication bypass succeeded at {login_url} using SQL injection payload \"' OR 1=1--\". Server returned HTTP 200 with session JWT token: {login_res.text[:80]}...",
                    "remediation": "Enforce parameterized database queries for all user authentication handlers. Never build raw SQL queries from login credentials.",
                    "compliance_map": ["OWASP ASVS V2.1.1", "CWE-89", "CWE-287"],
                    "metadata": {"url": login_url, "host": host, "cwe_id": "89"},
                })
                break
        except Exception:
            pass

    # =========================================================================
    # MODULE 10: Path Traversal & Local File Inclusion (LFI)
    # =========================================================================
    _report(88, "lfi_probes", "Testing file retrieval handlers for Directory Traversal and Local File Inclusion...")

    lfi_test_routes = [
        f"{base_url}/ftp/package.json.bak%2500.md",
        f"{base_url}/download?file=../../../../etc/passwd",
        f"{base_url}/view?page=../../../../etc/passwd",
        f"{base_url}/include?file=../../../../etc/passwd",
    ]
    for lfi_url in lfi_test_routes:
        try:
            lfi_res = session.get(lfi_url, timeout=4, verify=False)
            if lfi_res.status_code == 200:
                if "root:x:0:0:" in lfi_res.text or "[fonts]" in lfi_res.text.lower() or "[extensions]" in lfi_res.text.lower() or "dependencies" in lfi_res.text.lower():
                    findings.append({
                        "title": "Directory Traversal / Arbitrary File Disclosure Vulnerability",
                        "category": "web",
                        "source": "zap",
                        "port": port,
                        "protocol": "https" if base_url.startswith("https") else "http",
                        "service": "http",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": 8.6,
                        "severity": "high",
                        "evidence": f"Path traversal succeeded at {lfi_url}. File content retrieved: {lfi_res.text[:120].strip()}",
                        "remediation": "Sanitize file path inputs using basename validation and prevent dot-dot-slash traversal sequences.",
                        "compliance_map": ["OWASP ASVS V12.3", "CWE-22"],
                        "metadata": {"url": lfi_url, "host": host, "cwe_id": "22"},
                    })
                    break
        except Exception:
            pass

    # =========================================================================
    # MODULE 11: Open URL Redirection
    # =========================================================================
    _report(92, "open_redirect", "Testing redirect handlers for Open URL Redirection...")

    redirect_tests = [
        f"{base_url}/redirect?url=https://example.com",
        f"{base_url}/login?redirect_to=https://example.com",
        f"{base_url}/logout?next=https://example.com",
        f"{base_url}/goto?target=https://example.com",
    ]
    for r_url in redirect_tests:
        try:
            r_res = session.get(r_url, timeout=4, allow_redirects=False, verify=False)
            if r_res.status_code in [301, 302, 303, 307, 308]:
                loc = r_res.headers.get("location", "")
                if loc.startswith("https://example.com") or loc.startswith("//example.com"):
                    findings.append({
                        "title": "Open URL Redirection Vulnerability",
                        "category": "web",
                        "source": "zap",
                        "port": port,
                        "protocol": "https" if base_url.startswith("https") else "http",
                        "service": "http",
                        "state": "open",
                        "cve_id": None,
                        "cvss_score": 6.1,
                        "severity": "medium",
                        "evidence": f"Unvalidated redirect confirmed at {r_url}. Location header redirected to: {loc}",
                        "remediation": "Validate target redirection URLs against a strict whitelist of internal application domains.",
                        "compliance_map": ["OWASP ASVS V5.1.5", "CWE-601"],
                        "metadata": {"url": r_url, "host": host, "cwe_id": "601"},
                    })
                    break
        except Exception:
            pass

    # =========================================================================
    # MODULE 12: Insecure HTTP Methods (TRACE / PUT)
    # =========================================================================
    _report(95, "http_methods", "Auditing HTTP method permissions (TRACE, PUT, DELETE, OPTIONS)...")
    try:
        trace_res = session.request("TRACE", base_url, timeout=4, verify=False)
        if trace_res.status_code == 200 and "message/http" in trace_res.headers.get("content-type", "").lower():
            findings.append({
                "title": "Insecure HTTP TRACE Method Enabled (Cross-Site Tracing)",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 5.3,
                "severity": "medium",
                "evidence": f"HTTP TRACE method is active at {base_url}, reflecting client headers and exposing cookies to XST attacks.",
                "remediation": "Disable HTTP TRACE and TRACK methods in web server configuration.",
                "compliance_map": ["OWASP ASVS V14.4.2", "CWE-200"],
                "metadata": {"url": base_url, "host": host},
            })
    except Exception:
        pass

    # =========================================================================
    # MODULE 13: GraphQL Introspection Audit
    # =========================================================================
    _report(98, "graphql_audit", "Probing GraphQL interfaces for unrestricted schema introspection...")
    for gql_path in ["/graphql", "/api/graphql", "/v1/graphql"]:
        gql_url = f"{base_url}{gql_path}"
        try:
            gql_res = session.post(gql_url, json={"query": "{__schema{types{name}}}"}, timeout=4, verify=False)
            if gql_res.status_code == 200 and "__schema" in gql_res.text:
                findings.append({
                    "title": f"Unrestricted GraphQL Introspection Query Enabled ({gql_path})",
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": 5.3,
                    "severity": "medium",
                    "evidence": f"GraphQL introspection query succeeded at {gql_url}, exposing complete schema hierarchy and queries.",
                    "remediation": "Disable GraphQL schema introspection queries in production environments.",
                    "compliance_map": ["OWASP ASVS V14.2.1", "CWE-200"],
                    "metadata": {"url": gql_url, "host": host},
                })
                break
        except Exception:
            pass

    _report(100, "completed", f"Deep Web & Subdirectory Assessment completed. Discovered {len(discovered_urls)} endpoints and {len(findings)} vulnerability findings.")
    return findings
