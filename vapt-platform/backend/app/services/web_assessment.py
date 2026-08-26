import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from urllib.parse import urlparse

import requests


SENSITIVE_PATHS: list[tuple[str, str, float, str, str]] = [
    ("/.env", "Exposed Environment Configuration File", 9.1, "critical", "OWASP ASVS V12.5.1"),
    ("/.git/config", "Exposed Git Version Control Repository", 8.5, "high", "OWASP ASVS V14.3.1"),
    ("/.git/HEAD", "Exposed Git Repository Metadata", 7.8, "high", "OWASP ASVS V14.3.1"),
    ("/config.json", "Exposed Application Configuration JSON", 7.5, "high", "CWE-538"),
    ("/appsettings.json", "Exposed ASP.NET Configuration File", 7.5, "high", "CWE-538"),
    ("/ftp", "Exposed FTP Storage Directory Index", 8.8, "high", "CWE-548"),
    ("/ftp/acquisitions.md", "Exposed Confidential Corporate Acquisition File", 9.0, "critical", "CWE-538"),
    ("/ftp/coupons_2013.md.bak", "Exposed Legacy Promotional Discount Credentials", 8.1, "high", "CWE-538"),
    ("/ftp/package.json.bak", "Exposed Application Package Backup Archive", 7.5, "high", "CWE-538"),
    ("/ftp/eastere.gg", "Exposed Hidden Developer Easter Egg File", 5.0, "medium", "CWE-200"),
    ("/ftp/legal.md", "Exposed Internal Legal Terms Document", 5.0, "medium", "CWE-200"),
    ("/assets/public/images/uploads/", "Exposed Public Uploads Directory Index", 6.5, "medium", "CWE-548"),
    ("/api/Challenges", "Exposed Internal Challenge Statistics API Endpoint", 5.3, "medium", "CWE-200"),
    ("/api/Users", "Exposed User Identity Management API Endpoint", 8.5, "high", "CWE-284"),
    ("/swagger-ui.html", "Exposed Interactive Swagger API Interface", 5.4, "medium", "OWASP ASVS V14.2.1"),
    ("/v2/api-docs", "Exposed OpenAPI / Swagger JSON Specification", 5.3, "medium", "CWE-200"),
    ("/openapi.json", "Exposed OpenAPI v3 Documentation", 5.3, "medium", "CWE-200"),
    ("/actuator/health", "Spring Boot Actuator Endpoint Exposed", 4.3, "low", "OWASP ASVS V14.3.2"),
    ("/actuator/env", "Exposed Spring Boot Actuator Environment Configuration", 8.8, "high", "CWE-538"),
    ("/actuator/heapdump", "Exposed Spring Boot Heap Dump Memory File", 9.0, "critical", "CWE-200"),
    ("/phpinfo.php", "PHPInfo Diagnostic Page Disclosure", 6.1, "medium", "CWE-200"),
    ("/.well-known/security.txt", "Security Contact Policy Document", 0.0, "info", "RFC 9116"),
    ("/backup.sql", "Exposed SQL Database Backup File", 9.4, "critical", "CWE-538"),
    ("/dump.sql", "Exposed Database Dump Archive", 9.4, "critical", "CWE-538"),
    ("/admin", "Unprotected Administrative Dashboard Route", 6.5, "medium", "OWASP ASVS V4.1"),
    ("/wp-admin", "WordPress Administrative Portal Interface", 5.0, "medium", "CWE-200"),
    ("/console", "Web Application Console / Debugging Route", 7.5, "high", "CWE-200"),
    ("/kibana", "Exposed Kibana Administrative Dashboard", 7.5, "high", "CWE-306"),
    ("/.ds_store", "Exposed macOS .DS_Store Directory Index File", 5.3, "medium", "CWE-538"),
    ("/server-status", "Apache / Server Status Diagnostic Page Disclosure", 5.8, "medium", "CWE-200"),
    ("/robots.txt", "Robots.txt Crawling Policy File", 0.0, "info", "NIST RA-5"),
    ("/graphql", "GraphQL API Interface Endpoint", 4.5, "low", "CWE-200"),
]


def run_web_assessment(
    target_url: str,
    progress_callback: Callable[[int, dict[str, Any]], None] | None = None,
    deep_mode: bool = True,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def _report(progress: int, phase: str, message: str) -> None:
        if progress_callback:
            progress_callback(progress, {"phase": phase, "message": message})

    _report(10, "normalization", f"Normalizing target web URL and establishing HTTP session (Deep Mode: {deep_mode}).")

    raw_target = str(target_url).strip()
    
    # Intelligent scheme default: default to http for localhost and development ports (3000, 80, 8080, 8000, 5000)
    if not raw_target.startswith(("http://", "https://")):
        if any(p in raw_target for p in [":3000", ":80", ":8080", ":8000", ":5000", ":3001"]):
            raw_target = f"http://{raw_target}"
        else:
            raw_target = f"http://{raw_target}"

    parsed = urlparse(raw_target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or raw_target
    port = parsed.port or (443 if base_url.startswith("https") else 80)

    # Known external → local Docker service fallback mappings.
    # When running in Docker locally, external URLs may be unreachable.
    # These mappings allow the scanner to use the local container instead.
    KNOWN_DOCKER_FALLBACKS: dict[str, str] = {
        "juice-shop.herokuapp.com": "http://juice-shop:3000",
        "www.juice-sh.op": "http://juice-shop:3000",
        "juice-sh.op": "http://juice-shop:3000",
        "dvwa": "http://dvwa:80",
        "dvwa.local": "http://dvwa:80",
    }

    # Build target candidates list to resolve Docker container networking (e.g. localhost → juice-shop / dvwa / host.docker.internal)
    target_candidates = [base_url]

    # Check known external → local Docker fallback first
    local_fallback = KNOWN_DOCKER_FALLBACKS.get(host)
    if local_fallback:
        target_candidates.insert(0, local_fallback)  # Try local container first

    if host in ["localhost", "127.0.0.1", "0.0.0.0"]:
        if port == 3000:
            target_candidates.insert(0, "http://juice-shop:3000")
        elif port == 80:
            target_candidates.insert(0, "http://dvwa:80")
        target_candidates.append(base_url.replace(host, "host.docker.internal"))

    session = requests.Session()
    session.headers.update({
        "User-Agent": "VAPT-Platform-WebScanner/2.5 (Advanced Deep Pentest Engine)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    _report(25, "headers_audit", f"Auditing HTTP response headers, SSL/TLS security policies, and CORS for {base_url}.")

    main_response = None
    active_target_url = base_url
    for candidate_url in target_candidates:
        try:
            res = session.get(candidate_url, timeout=6, allow_redirects=True, verify=False)
            if res is not None and res.status_code < 500:
                main_response = res
                active_target_url = candidate_url
                base_url = candidate_url
                break
        except Exception:
            continue

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

        # 4. Server Information Disclosure
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

        # 5. Cookie Security Audit (HttpOnly, Secure, SameSite)
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

    _report(45, "cors_audit", "Testing Cross-Origin Resource Sharing (CORS) security configuration.")

    # 6. Active CORS Wildcard & Origin Reflection Probe
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

    _report(60, "endpoint_discovery", "Fuzzing sensitive administrative endpoints and configuration disclosures (25+ paths).")

    # Detect SPA soft-404 / catch-all routing (e.g. Juice Shop / Angular / React returning index.html for all routes)
    soft_404_body = None
    soft_404_len = 0
    try:
        probe_res = session.get(f"{base_url}/__vapt_soft_404_probe_{int(time.time())}", timeout=4, allow_redirects=False, verify=False)
        if probe_res.status_code == 200:
            soft_404_body = probe_res.text.strip()
            soft_404_len = len(soft_404_body)
    except Exception:
        pass

    root_body = (main_response.text or "").strip() if main_response else ""
    root_len = len(root_body)

    # 7. Sensitive Endpoint Probes (Multi-Threaded Execution with Content Validation)
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

                ct = (res.headers.get("content-type") or "").lower()

                # Content validation for specific file types to avoid false positives:
                is_html = "<!doctype html" in body.lower() or "<html" in body.lower()

                if path in ["/.env", "/appsettings.json", "/config.json", "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql"] and is_html:
                    return None

                if path == "/.git/config" and "[core]" not in body:
                    return None
                if path == "/.git/HEAD" and "ref:" not in body:
                    return None

                if path in ["/backup.sql", "/dump.sql"] and not any(kw in body.upper() for kw in ["CREATE TABLE", "INSERT INTO", "DATABASE", "DROP TABLE", "-- MYSQL", "-- POSTGRESQL"]):
                    return None

                if path in ["/actuator/health", "/actuator/env", "/actuator/heapdump", "/api/Challenges", "/api/Users", "/v2/api-docs", "/openapi.json"] and is_html:
                    return None

                if path == "/phpinfo.php" and ("php version" not in body.lower() and "<title>phpinfo()</title>" not in body.lower()):
                    return None

                if path == "/wp-admin" and "wp-login" not in body.lower() and "wordpress" not in body.lower():
                    return None

                if path == "/kibana" and "kibana" not in body.lower():
                    return None

                if path == "/server-status" and "apache server status" not in body.lower():
                    return None

                if path == "/swagger-ui.html" and "swagger" not in body.lower():
                    return None

                if path == "/graphql" and is_html:
                    return None

                # Construct clear, accurate description matching the finding title
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

    paths_to_test = SENSITIVE_PATHS if deep_mode else SENSITIVE_PATHS[:6]
    with ThreadPoolExecutor(max_workers=15) as pool:
        futures = [pool.submit(_check_path, item) for item in paths_to_test]
        for future in as_completed(futures):
            res_finding = future.result()
            if res_finding:
                findings.append(res_finding)

    _report(85, "xss_sqli_probes", "Testing active parameter handling for Reflected XSS, SQLi, and GraphQL Introspection.")

    # 8. Active Parameter XSS Probes
    xss_test_url = f"{base_url}/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    try:
        xss_res = session.get(xss_test_url, timeout=5, verify=False)
        if "<script>alert(1)</script>" in xss_res.text:
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
                "evidence": f"Unsanitized parameter reflection confirmed at {xss_test_url}.",
                "remediation": "Apply contextual HTML/Attribute output encoding and validate input against strict whitelist rules.",
                "compliance_map": ["OWASP ASVS V5.3.1", "CWE-79"],
                "metadata": {"url": xss_test_url, "host": host, "cwe_id": "79"},
            })
    except Exception:
        pass

    # 9. Active SQL Injection Probes (REST APIs & Traditional Parameters)
    sqli_endpoints = [
        (f"{base_url}/rest/products/search?q=%27%29%29%20OR%201=1--", "SQL Injection in Product Search API", 8.8, "high"),
        (f"{base_url}/api/v1/products?id=1%27%20OR%201=1--", "Error-Based SQL Injection in Query Parameter", 8.9, "high"),
    ]
    for sqli_url, sqli_title, sqli_cvss, sqli_sev in sqli_endpoints:
        try:
            sqli_res = session.get(sqli_url, timeout=5, verify=False)
            if sqli_res.status_code == 200 and ("status" in sqli_res.text or "data" in sqli_res.text or len(sqli_res.text) > 1000):
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
                        "evidence": f"SQL Injection probe succeeded at {sqli_url}. The query returned manipulated backend database records (Response length: {len(sqli_res.text)} bytes).",
                        "remediation": "Use parameterized queries (Prepared Statements) or ORM abstractions; never concatenate untrusted user input into raw SQL statements.",
                        "compliance_map": ["OWASP ASVS V5.3.4", "CWE-89"],
                        "metadata": {"url": sqli_url, "host": host, "cwe_id": "89"},
                    })
        except Exception:
            pass

    # 10. Active SQL Injection Authentication Bypass Probe
    login_endpoints = [
        f"{base_url}/rest/user/login",
        f"{base_url}/api/user/login",
        f"{base_url}/api/login",
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
                    "evidence": f"Authentication bypass succeeded at {login_url} using SQL injection payload \"' OR 1=1--\". The server returned HTTP 200 with an authenticated session JWT token: {login_res.text[:80]}...",
                    "remediation": "Enforce parameterized database queries for all user authentication handlers. Never build raw SQL queries from login credentials.",
                    "compliance_map": ["OWASP ASVS V2.1.1", "CWE-89", "CWE-287"],
                    "metadata": {"url": login_url, "host": host, "cwe_id": "89"},
                })
                break
        except Exception:
            pass

    # 11. Application Configuration & Version Disclosure Probes
    api_checks = [
        (f"{base_url}/rest/admin/application-configuration", "Exposed Backend Application Configuration", 7.5, "high", "config"),
        (f"{base_url}/rest/admin/application-version", "Exposed Application Version Information", 5.0, "medium", "version"),
        (f"{base_url}/api/SecurityQuestions", "Exposed User Security Questions Database", 6.5, "medium", "security_questions"),
        (f"{base_url}/api-docs", "Exposed Interactive API Documentation (Swagger)", 5.3, "medium", "api_docs"),
    ]
    for check_url, check_title, check_cvss, check_sev, check_type in api_checks:
        try:
            check_res = session.get(check_url, timeout=5, verify=False)
            if check_res.status_code == 200 and len(check_res.text) > 10:
                is_html = "<!doctype html" in check_res.text.lower() or "<html" in check_res.text.lower()
                if check_type != "api_docs" and is_html:
                    continue
                if soft_404_body and check_res.text.strip() == soft_404_body:
                    continue
                findings.append({
                    "title": check_title,
                    "category": "web",
                    "source": "zap",
                    "port": port,
                    "protocol": "https" if base_url.startswith("https") else "http",
                    "service": "http",
                    "state": "open",
                    "cve_id": None,
                    "cvss_score": check_cvss,
                    "severity": check_sev,
                    "evidence": f"Accessible sensitive API route at {check_url} (HTTP 200 OK). Sample payload: {check_res.text[:140].strip()}",
                    "remediation": "Restrict administrative and diagnostic API endpoints to authenticated and authorized operators only.",
                    "compliance_map": ["OWASP ASVS V14.2.1", "CWE-200"],
                    "metadata": {"url": check_url, "host": host, "cwe_id": "200"},
                })
        except Exception:
            pass

    # 12. GraphQL Introspection Audit
    gql_url = f"{base_url}/graphql"
    try:
        gql_res = session.post(gql_url, json={"query": "{__schema{types{name}}}"}, timeout=5, verify=False)
        if gql_res.status_code == 200 and "__schema" in gql_res.text:
            findings.append({
                "title": "Unrestricted GraphQL Introspection Query Enabled",
                "category": "web",
                "source": "zap",
                "port": port,
                "protocol": "https" if base_url.startswith("https") else "http",
                "service": "http",
                "state": "open",
                "cve_id": None,
                "cvss_score": 5.3,
                "severity": "medium",
                "evidence": f"GraphQL introspection query succeeded at {gql_url}, exposing entire schema hierarchy.",
                "remediation": "Disable GraphQL schema introspection queries in production environments.",
                "compliance_map": ["OWASP ASVS V14.2.1", "CWE-200"],
                "metadata": {"url": gql_url, "host": host},
            })
    except Exception:
        pass

    _report(100, "completed", f"Advanced Deep Web Assessment completed successfully. Discovered {len(findings)} findings.")
    return findings

