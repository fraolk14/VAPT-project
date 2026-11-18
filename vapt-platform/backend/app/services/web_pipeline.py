"""Extra web-assessment stages that run around ZAP, to cut false negatives and false positives.

    crawl    Katana (parses JavaScript for endpoints ZAP's spider misses); URLs are fed into ZAP
    find     Nuclei: signature templates for known CVEs, exposures and misconfigurations
    tls      testssl.sh: protocol, cipher, certificate and TLS-vulnerability checks, once per host
    confirm  Dalfox (XSS) and sqlmap (SQL injection, detection only) replay ZAP's exact request;
             confirmed findings get high confidence, ones that don't reproduce get low confidence
    merge    the same issue reported by several engines becomes one finding listing every source

Every stage is optional: a missing tool or a timeout records a warning and the scan continues.
Nothing here exploits or extracts data: sqlmap runs at level 1 / risk 1 with no dump options,
and Nuclei excludes DoS, brute-force and intrusive templates.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Every engine whose findings are web-application findings.
WEB_SOURCES = frozenset({"zap", "web", "nuclei", "testssl"})
STATIC_EXT = "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,otf,mp4,mp3,webm,webp,avif,pdf,zip,gz,map"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _first_byte_seconds(url: str, timeout: float = 10) -> float:
    """Seconds until the response headers arrive. The body is not downloaded, so a slow internet
    link does not make a healthy site look slow. Raises on DNS, connection or timeout errors."""
    import time

    import requests

    t0 = time.time()
    with requests.get(url, timeout=timeout, allow_redirects=False, verify=False, stream=True,
                      headers={"User-Agent": "Mozilla/5.0 (compatible; VAPT-Platform)"}):
        return time.time() - t0


def probe_target(target: str, connect_timeout: float = 10, read_timeout: float = 25) -> tuple[bool, str]:
    """Check, before any engine starts, that the scanner can reach the target at all.

    Returns (reachable, plain-language detail). Distinguishes DNS failure, a connection that is
    refused or never answers (site down, or the host/firewall blocking this network), and a site
    that accepts the connection but never sends a response.
    """
    import socket

    import requests

    host, port, scheme = _host_port(target)
    try:
        addr = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)[0][4][0]
    except OSError:
        return False, f"The scanner could not resolve {host} in DNS. Check the address, or the server's DNS settings."
    try:
        with socket.create_connection((addr, port), timeout=connect_timeout):
            pass
    except ConnectionRefusedError:
        return False, f"{host} ({addr}) refused the connection on port {port}. Nothing is listening there, or a firewall rejects it."
    except OSError:
        return False, (f"The scanner could not connect to {host} ({addr}) on port {port}: no answer within "
                       f"{int(connect_timeout)}s. The site may be down, or its host or a firewall may be blocking "
                       "this network's IP address (hosting providers often block an IP after scanner traffic). "
                       "Check that the site opens from another network, then allow-list the scanner's public IP.")
    try:
        seconds = _first_byte_seconds(_base(target), timeout=read_timeout)
    except requests.RequestException as exc:
        return False, (f"{host} accepted the connection on port {port} but sent no usable response "
                       f"within {int(read_timeout)}s ({type(exc).__name__}).")
    return True, f"{host} ({addr}) answered in {seconds:.1f}s."


def wait_for_target(target: str, max_wait: int | None = None) -> tuple[bool, float, bool]:
    """Wait until the target answers quickly (first byte under 3 s) twice in a row.

    Heavy active scanning can leave an app sluggish for a while. Testing it in that state produces
    false positives (timing checks) and false negatives (timeouts), so each later stage waits here.
    Returns (responsive, seconds waited, answered at least once).
    """
    import time

    limit = max_wait if max_wait is not None else _env_int("TARGET_RECOVERY_SECONDS", 180)
    start, fast, answered = time.time(), 0, False
    while True:
        try:
            seconds = _first_byte_seconds(_base(target))
            answered = True
            fast = fast + 1 if seconds < 3 else 0
        except Exception:
            fast = 0
        if fast >= 2:
            return True, round(time.time() - start, 1), True
        if time.time() - start > limit:
            return False, round(time.time() - start, 1), answered
        time.sleep(5)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int, cwd: str | None = None) -> tuple[int, str, str]:
    """Run a tool with a hard timeout. Returns (exit code, stdout, stderr); -9 means timed out."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, errors="replace")
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return -9, out, "timed out"
    except OSError as exc:
        return -1, "", str(exc)


def _host_port(url: str) -> tuple[str, int, str]:
    p = urlparse(url if "://" in url else f"http://{url}")
    scheme = p.scheme or "http"
    return (p.hostname or "").lower(), p.port or (443 if scheme == "https" else 80), scheme


def _base(url: str) -> str:
    p = urlparse(url if "://" in url else f"http://{url}")
    return f"{p.scheme or 'http'}://{p.netloc}"


# ---------------------------------------------------------------------------
# Crawl: Katana
# ---------------------------------------------------------------------------

def katana_crawl(target: str) -> tuple[list[str], list[str]]:
    """Return (same-host URLs found, warnings)."""
    if not tool_available("katana"):
        return [], ["Katana is not installed; JavaScript endpoint discovery was skipped."]
    seconds = _env_int("KATANA_MAX_SECONDS", 180)
    cmd = [
        "katana", "-u", target, "-silent", "-jsonl", "-nc",
        "-jc",                  # parse JavaScript files for endpoints
        "-kf", "all",           # also read robots.txt and sitemap.xml
        "-d", str(_env_int("KATANA_DEPTH", 3)),
        "-c", "5", "-rl", str(_env_int("KATANA_RATE_LIMIT", 40)),
        "-timeout", "10", "-ct", f"{seconds}s",
        "-fs", "fqdn",          # stay on the exact host being assessed
        "-ef", STATIC_EXT,
    ]
    code, out, err = _run(cmd, timeout=seconds + 30)
    host = _host_port(target)[0]
    urls: list[str] = []
    seen: set[str] = set()
    for line in out.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        endpoint = ((row.get("request") or {}).get("endpoint") or "").strip()
        if not endpoint or _host_port(endpoint)[0] != host or endpoint in seen:
            continue
        seen.add(endpoint)
        urls.append(endpoint)
    warnings = []
    if code not in (0, -9) and not urls:
        warnings.append(f"Katana crawl failed ({err.strip()[:160] or code}).")
    if code == -9:
        warnings.append(f"Katana crawl stopped at its {seconds}s limit; {len(urls)} URLs collected.")
    return urls[: _env_int("KATANA_MAX_URLS", 500)], warnings


def feed_urls_to_zap(zap_client: Any, urls: list[str]) -> int:
    """Request each URL through ZAP so the active scan covers endpoints its spider missed."""
    fed = 0
    for url in urls[: _env_int("ZAP_FEED_MAX_URLS", 300)]:
        try:
            zap_client._request("core", "action", "accessUrl", _timeout=20, url=url, followRedirects="false")
            fed += 1
        except Exception:
            continue
    return fed


# ---------------------------------------------------------------------------
# Find: Nuclei
# ---------------------------------------------------------------------------

def _nuclei_severity(value: str | None) -> str:
    value = (value or "info").lower()
    return value if value in SEV_ORDER else "info"


def run_nuclei(target: str, crawled: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Signature checks on the site root, plus DAST templates on crawled URLs that take parameters."""
    if not tool_available("nuclei"):
        return [], ["Nuclei is not installed; known-CVE and exposure checks were skipped."]
    templates = os.getenv("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
    seconds = _env_int("NUCLEI_MAX_SECONDS", 1500)
    # Pace: ~25k requests for the full low+ HTTP set, ~11 min at 40 req/s. A low max-host-error cap
    # makes Nuclei abandon an app that is briefly slow, which silently skips most checks, so it is high.
    common = [
        # No -silent: results still go to stdout as JSONL, and stderr keeps Nuclei's
        # "Skipped <host> ... unresponsive" notice, the only reliable sign a pass was cut short.
        "-jsonl", "-nc", "-duc", "-omit-raw",
        # -sr: fall back to the system resolver. Nuclei otherwise retries public resolvers, which cannot
        # resolve internal names (docker services, intranet hosts); one failed lookup marks the host dead.
        "-sr",
        "-severity", os.getenv("NUCLEI_SEVERITY", "low,medium,high,critical"),
        "-etags", "dos,fuzz-dos,brute-force,bruteforce,intrusive,headless",
        "-rl", str(_env_int("NUCLEI_RATE_LIMIT", 40)), "-c", "10", "-bs", "10",
        "-timeout", "10", "-retries", "1",
        "-stats", "-sj", "-si", "30",
    ]
    # Host-error skipping is off by default: some path-traversal templates make Nuclei's own host lookup
    # fail ("no address found for host"), which it treats as permanent and then skips the whole target
    # after a few percent of the checks. A target that really goes down is bounded by the time limit
    # below (and reported). Set NUCLEI_MAX_HOST_ERRORS to restore skipping.
    common += ["-mhe", os.environ["NUCLEI_MAX_HOST_ERRORS"]] if os.getenv("NUCLEI_MAX_HOST_ERRORS") else ["-nmhe"]
    if os.getenv("NUCLEI_INTERACTSH", "0") != "1":
        # Out-of-band checks send callbacks through public oast.* servers. Off unless enabled.
        common.append("-ni")

    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        # 1) Signature templates (CVEs, exposures, misconfigurations, default logins) against the root.
        root_file = Path(tmp, "roots.txt")
        root_file.write_text(_base(target) + "\n", encoding="utf-8")
        cmd = ["nuclei", "-l", str(root_file), "-t", templates, "-pt", "http", *common]
        code, out, err = _run(cmd, timeout=seconds)
        findings += _parse_nuclei(out)
        done = _nuclei_percent(err)
        if code == -9:
            warnings.append(f"Nuclei signature scan stopped at its {seconds}s limit after {done if done is not None else '?'}% of its checks; results are partial.")
        elif code not in (0, 1) and not out:
            warnings.append(f"Nuclei signature scan failed ({err.strip()[-160:] or code}).")
        elif _nuclei_gave_up(err):
            warnings.append(f"Nuclei stopped early because the target stopped responding (about {done if done is not None else '?'}% "
                            "of its checks ran); results are partial. Re-run when the target is stable.")

        # 2) DAST templates (XSS, SQLi, SSRF, LFI, redirects...) on crawled URLs that carry parameters,
        #    as an independent second detector next to ZAP's active scan.
        if os.getenv("NUCLEI_DAST", "1") == "1":
            param_urls = [u for u in crawled if "?" in u][: _env_int("NUCLEI_DAST_MAX_URLS", 40)]
            if param_urls:
                dast_file = Path(tmp, "dast.txt")
                dast_file.write_text("\n".join(param_urls) + "\n", encoding="utf-8")
                cmd = ["nuclei", "-l", str(dast_file), "-t", templates, "-dast", *common]
                code, out, err = _run(cmd, timeout=_env_int("NUCLEI_DAST_MAX_SECONDS", 600))
                findings += _parse_nuclei(out)
                done = _nuclei_percent(err)
                if code == -9:
                    warnings.append("Nuclei DAST pass stopped at its time limit; results are partial.")
                elif _nuclei_gave_up(err):
                    warnings.append(f"Nuclei DAST pass stopped early because the target stopped responding (about {done if done is not None else '?'}% ran).")
    return _group(findings), warnings


def _nuclei_gave_up(stderr: str) -> bool:
    return "found unresponsive" in stderr


def _nuclei_percent(stderr: str) -> int | None:
    """Last 'percent' from Nuclei's JSON stats lines (-stats -sj), or None if there were none."""
    last = None
    for line in stderr.splitlines():
        if '"percent"' in line:
            try:
                last = int(json.loads(line[line.index("{"):]).get("percent"))
            except (ValueError, TypeError):
                continue
    return last


_TIME_BASED = re.compile(r"time[- _]?based|\bsleep\b|\bdelay\b|\bblind\b", re.I)


def _parse_nuclei(output: str) -> list[dict[str, Any]]:
    results = []
    for line in output.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        info = row.get("info") or {}
        cls = info.get("classification") or {}
        cves = [c.upper() for c in (cls.get("cve-id") or []) if c]
        cwes = [c.upper() for c in (cls.get("cwe-id") or []) if c]
        matched = row.get("matched-at") or row.get("host") or ""
        host, port, scheme = _host_port(matched)
        name = info.get("name") or row.get("template-id") or "Nuclei finding"
        if row.get("matcher-name"):
            name = f"{name} ({row['matcher-name']})"
        extracted = row.get("extracted-results") or []
        evidence = f"Nuclei template '{row.get('template-id')}' matched at {matched}."
        if extracted:
            evidence += " Extracted: " + ", ".join(str(x) for x in extracted[:5])
        if row.get("fuzzing-parameter"):
            evidence += f" Parameter: {row['fuzzing-parameter']}."
        refs = info.get("reference") or []
        results.append({
            "title": name[:200],
            "category": "web",
            "source": "nuclei",
            "port": port,
            "protocol": scheme,
            "service": scheme,
            "state": "open",
            "cve_id": ", ".join(cves) or None,
            "cvss_score": cls.get("cvss-score"),
            "severity": _nuclei_severity(info.get("severity")),
            # A template fires only on an exact response signature, so a match is strong evidence.
            "confidence": 0.9,
            "evidence": evidence,
            "remediation": info.get("remediation") or (
                f"See the references for {', '.join(cves)}." if cves else "Restrict or remove the exposed resource, then re-scan."),
            "compliance_map": [c for c in ["OWASP Top 10", *cwes] if c],
            "metadata": {
                "url": matched,
                "host": host,
                "template_id": row.get("template-id"),
                "template_path": row.get("template-path"),
                "matcher": row.get("matcher-name"),
                "tags": info.get("tags"),
                "description": info.get("description"),
                "reference": "\n".join(refs if isinstance(refs, list) else [str(refs)]),
                "cwe_id": (cwes[0].replace("CWE-", "") if cwes else None),
                "cve_refs": cves,
                "param": row.get("fuzzing-parameter"),
                "input_url": row.get("url") or matched,
                "time_based": bool(_TIME_BASED.search(" ".join([name, str(row.get("template-id") or ""), str(info.get("tags") or "")]))),
                "curl_command": (row.get("curl-command") or "")[:1500],
            },
        })
    return results


def _group(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per (template/issue, host), listing affected URLs."""
    grouped: dict[tuple, dict[str, Any]] = {}
    for f in findings:
        meta = f.get("metadata") or {}
        key = (meta.get("template_id") or f["title"], f.get("title"), meta.get("host"), f.get("port"))
        if key not in grouped:
            grouped[key] = {**f, "metadata": {**meta, "affected_urls": []}}
        entry = grouped[key]
        if meta.get("url") and meta["url"] not in entry["metadata"]["affected_urls"]:
            entry["metadata"]["affected_urls"].append(meta["url"])
    for entry in grouped.values():
        entry["metadata"]["occurrences"] = len(entry["metadata"]["affected_urls"]) or 1
        entry["metadata"]["affected_urls"] = entry["metadata"]["affected_urls"][:50]
    return list(grouped.values())


# ---------------------------------------------------------------------------
# TLS: testssl.sh
# ---------------------------------------------------------------------------

_TLS_TITLES = {
    "SSLv2": "SSLv2 protocol enabled", "SSLv3": "SSLv3 protocol enabled", "TLS1": "TLS 1.0 enabled",
    "TLS1_1": "TLS 1.1 enabled", "heartbleed": "Heartbleed (CVE-2014-0160)", "CCS": "OpenSSL CCS injection",
    "ticketbleed": "Ticketbleed", "ROBOT": "ROBOT attack", "secure_renego": "Insecure TLS renegotiation",
    "secure_client_renego": "Client-initiated TLS renegotiation", "CRIME_TLS": "CRIME (TLS compression)",
    "BREACH": "BREACH (HTTP compression)", "POODLE_SSL": "POODLE (SSLv3)", "SWEET32": "SWEET32 (64-bit block ciphers)",
    "FREAK": "FREAK (export RSA)", "DROWN": "DROWN", "LOGJAM": "LOGJAM (weak DH)", "BEAST": "BEAST",
    "LUCKY13": "LUCKY13", "RC4": "RC4 ciphers offered", "cert_expirationStatus": "TLS certificate expired or expiring",
    "cert_chain_of_trust": "TLS certificate not trusted", "cert_trust": "TLS certificate name mismatch",
    "cert_signatureAlgorithm": "Weak certificate signature algorithm", "cert_keySize": "Weak certificate key size",
    "HSTS": "HSTS header missing or weak", "cipherlist_NULL": "NULL ciphers offered",
    "cipherlist_aNULL": "Anonymous ciphers offered", "cipherlist_EXPORT": "Export ciphers offered",
    "cipherlist_LOW": "Low-strength ciphers offered", "cipherlist_3DES_IDEA": "3DES/IDEA ciphers offered",
    "cipherlist_OBSOLETED": "Obsolete CBC ciphers offered", "FS": "No forward secrecy",
}
_TLS_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_testssl(target: str) -> tuple[list[dict[str, Any]], list[str]]:
    host, port, scheme = _host_port(target)
    if scheme != "https":
        return [], []
    if not tool_available("testssl.sh"):
        return [], ["testssl.sh is not installed; TLS checks were skipped."]
    seconds = _env_int("TESTSSL_MAX_SECONDS", 420)
    with tempfile.TemporaryDirectory() as tmp:
        out_file = Path(tmp, "tls.json")
        cmd = ["testssl.sh", "--quiet", "--color", "0", "--warnings", "batch", "--sneaky",
               "-p", "-S", "-U", "-s", "-h", "--jsonfile", str(out_file), f"{host}:{port}"]
        code, _out, err = _run(cmd, timeout=seconds)
        try:
            rows = json.loads(out_file.read_text(encoding="utf-8")) if out_file.exists() else []
        except ValueError:
            rows = []
    if not rows:
        reason = "timed out" if code == -9 else (err.strip()[:160] or f"exit {code}")
        return [], [f"testssl.sh produced no results ({reason})."]
    findings = []
    for row in rows:
        sev = _TLS_SEV.get(str(row.get("severity", "")).upper())
        if not sev:
            continue
        test_id = str(row.get("id") or "")
        title = _TLS_TITLES.get(test_id) or f"TLS weakness: {test_id}"
        cves = re.findall(r"CVE-\d{4}-\d{4,7}", str(row.get("cve") or ""), re.I)
        findings.append({
            "title": title,
            "category": "web",
            "source": "testssl",
            "port": port,
            "protocol": "https",
            "service": "https",
            "state": "open",
            "cve_id": ", ".join(sorted({c.upper() for c in cves})) or None,
            "cvss_score": {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}[sev],
            "severity": sev,
            "confidence": 0.95,  # testssl.sh observes the handshake directly
            "evidence": f"testssl.sh {test_id}: {row.get('finding')}",
            "remediation": "Disable the weak protocol/cipher or replace the certificate in the TLS configuration, then re-test.",
            "compliance_map": [c for c in ["PCI DSS 4.2.1", f"CWE-{row.get('cwe')}" if row.get("cwe") else None] if c],
            "metadata": {"url": f"https://{host}:{port}/", "host": host, "testssl_id": test_id,
                         "finding": row.get("finding"), "cve_refs": [c.upper() for c in cves]},
        })
    return findings, []


# ---------------------------------------------------------------------------
# Confirm: Dalfox (XSS) and sqlmap (SQL injection, detection only)
# ---------------------------------------------------------------------------

def _zap_raw_request(zap_client: Any, message_id: Any) -> str | None:
    if message_id in (None, ""):
        return None
    try:
        payload = zap_client._request("core", "view", "message", _timeout=20, id=str(message_id))
        msg = payload.get("message") or {}
        header = (msg.get("requestHeader") or "").replace("\r\n", "\n").rstrip("\n")
        body = msg.get("requestBody") or ""
        return f"{header}\n\n{body}" if header else None
    except Exception:
        return None


def _instances(finding: dict[str, Any]) -> list[dict[str, Any]]:
    meta = finding.get("metadata") or {}
    rows = list(meta.get("instances") or [])
    if not rows and meta.get("url"):
        rows = [{"url": meta.get("url"), "param": meta.get("param"), "method": meta.get("method"), "message_id": meta.get("message_id")}]
    return [r for r in rows if r.get("url") and r.get("param")]


def _split_raw(raw: str | None) -> tuple[list[str], str]:
    """Headers worth replaying (cookies, auth, content type) and the body from a ZAP raw request."""
    if not raw:
        return [], ""
    head, _, body = raw.partition("\n\n")
    keep = []
    for line in head.split("\n")[1:]:
        name = line.split(":", 1)[0].strip().lower()
        if ":" in line and name not in {"host", "content-length", "connection", "accept-encoding", "proxy-connection"}:
            keep.append(line.strip())
    return keep, body


def _confirm_sqli(zap_client: Any, inst: dict[str, Any], workdir: str) -> tuple[bool | None, str]:
    """sqlmap in detection mode only: level 1 / risk 1, no enumeration, no data read, no OS access.

    Returns True (injectable), False (sqlmap tested the parameter and found nothing) or
    None (inconclusive: timeout, target unreachable, request could not be replayed).
    """
    raw = _zap_raw_request(zap_client, inst.get("message_id"))
    https = str(inst.get("url", "")).lower().startswith("https")
    base = ["sqlmap", "--batch", "--level", "3", "--risk", "1", "--technique", "BEU",
            "--flush-session", "--disable-coloring", "--timeout", "10", "--retries", "1", "--threads", "4",
            "--output-dir", workdir, "-p", str(inst["param"])]
    if raw:
        req = Path(workdir, "req.txt")
        req.write_text(raw, encoding="utf-8")
        cmd = base + ["-r", str(req)] + (["--force-ssl"] if https else [])
    else:
        cmd = base + ["-u", inst["url"]]
    code, out, _err = _run(cmd, timeout=_env_int("SQLMAP_MAX_SECONDS", 300))
    proven = re.findall(r"parameter '[^']+' is '([^']+)' injectable", out)
    if proven or re.search(r"Parameter: .+\n(?:.*\n){0,3}?\s+Type: ", out) or "is vulnerable" in out:
        types = re.findall(r"Type: ([^\n]+)", out) or proven
        return True, f"sqlmap confirmed injectable parameter '{inst['param']}' ({'; '.join(sorted(set(types))) or 'injection'})."
    if code == -9:
        return None, "sqlmap timed out before reaching a verdict."
    if re.search(r"do(?:es)? not (?:seem|appear) to be injectable", out):
        return False, f"sqlmap tested '{inst['param']}' and found no injection."
    reason = next((ln.split("] ", 1)[-1] for ln in out.splitlines() if "[CRITICAL]" in ln), "no verdict in sqlmap output")
    return None, f"sqlmap could not complete the test: {reason[:160]}"


def _confirm_xss(zap_client: Any, inst: dict[str, Any], workdir: str) -> tuple[bool | None, str]:
    """Dalfox v3: only 'V' findings count (payload reached an executable position in the parsed DOM).

    Returns True (verified), False (Dalfox finished cleanly with no verified payload) or None
    (inconclusive: timeout, incomplete scan, failed requests).
    """
    headers, body = _split_raw(_zap_raw_request(zap_client, inst.get("message_id")))
    method = str(inst.get("method") or "GET").upper()
    out_file = Path(workdir, "dalfox.json")
    budget = _env_int("DALFOX_MAX_SECONDS", 180)
    cmd = ["dalfox", "scan", inst["url"], "-p", str(inst["param"]), "-X", method,
           "--format", "json", "-o", str(out_file), "-S", "--no-color", "--only-poc", "v",
           "--skip-mining", "--workers", "10", "--rate-limit", "40", "--timeout", "10", "--retries", "1",
           "--scan-timeout", str(max(30, budget - 30)), "--max-payloads-per-param", "400"]
    if method != "GET" and body:
        cmd += ["-d", body]
    for h in headers:
        cmd += ["-H", h]
    code, out, _err = _run(cmd, timeout=budget)
    try:
        data = json.loads(out_file.read_text(encoding="utf-8", errors="replace")) if out_file.exists() else {}
    except ValueError:
        data = {}
    findings = data.get("findings") if isinstance(data, dict) else None
    verified = [x for x in (findings or []) if isinstance(x, dict) and str(x.get("type", "")).upper() == "V"]
    if verified:
        v = verified[0]
        return True, (f"Dalfox verified XSS in '{v.get('param') or inst['param']}' ({v.get('inject_type') or 'reflected'}, "
                      f"{v.get('location') or method}) with payload {str(v.get('payload') or '')[:120]}")
    meta = data.get("meta") if isinstance(data, dict) else None
    if code == -9 or not isinstance(meta, dict):
        return None, "Dalfox timed out before reaching a verdict." if code == -9 else "Dalfox produced no report."
    if meta.get("incomplete") or (meta.get("failed_requests") or 0) > (meta.get("total_requests") or 0) // 2:
        return None, f"Dalfox scan was incomplete ({meta.get('failed_requests', 0)} of {meta.get('total_requests', 0)} requests failed)."
    return False, f"Dalfox sent {meta.get('total_requests', 0)} payload requests to '{inst['param']}'; none executed."


def confirm_injections(findings: list[dict[str, Any]], zap_client: Any) -> list[str]:
    """Replay ZAP's XSS and SQL injection findings with specialist tools. Mutates findings.

    confirmed      -> a specialist tool proved it; confidence >= 0.97
    not_reproduced -> the tool tested it cleanly and found nothing; confidence <= 0.35 (kept, flagged)
    inconclusive   -> the tool could not finish (timeout, unreachable); confidence unchanged
    """
    warnings: list[str] = []
    stamp = datetime.now(timezone.utc).isoformat()
    for f in findings:
        if f.get("source") != "zap":
            continue
        meta = f.get("metadata") or {}
        cwe = str(meta.get("cwe_id") or "")
        title = (f.get("title") or "").lower()
        kind = "sqli" if cwe == "89" or "sql injection" in title else "xss" if cwe == "79" or "cross site scripting" in title else None
        if not kind:
            continue
        tool = "sqlmap" if kind == "sqli" else "dalfox"
        if not tool_available(tool):
            warnings.append(f"{tool} is not installed; {kind.upper()} findings were not confirmed.")
            continue
        verdicts: list[bool | None] = []
        detail = "No replayable request with a parameter was recorded."
        confirm = _confirm_sqli if kind == "sqli" else _confirm_xss
        for inst in _instances(f)[: _env_int("CONFIRM_MAX_ATTEMPTS", 3)]:
            with tempfile.TemporaryDirectory() as tmp:
                ok, detail = confirm(zap_client, inst, tmp)
            verdicts.append(ok)
            if ok:
                break
        record = {"tool": tool, "detail": detail, "attempts": len(verdicts), "at": stamp}
        if not verdicts:
            meta["confirmation"] = {"status": "not_tested", **record}
        elif True in verdicts:
            f["confidence"] = max(float(f.get("confidence") or 0), 0.97)
            meta["confirmation"] = {"status": "confirmed", **record}
            f["evidence"] = f"{f.get('evidence') or ''} | CONFIRMED: {detail}".strip(" |")
        elif False in verdicts:
            f["confidence"] = min(float(f.get("confidence") or 0.5), 0.35)
            meta["confirmation"] = {"status": "not_reproduced", **record}
        else:
            meta["confirmation"] = {"status": "inconclusive", **record}
        f["metadata"] = meta
    return sorted(set(warnings))


def reverify_time_based(findings: list[dict[str, Any]]) -> list[str]:
    """Timing-based templates (e.g. ';sleep 5') misfire when the target is slow. Re-run each hit
    twice, one request at a time, after the heavy scanning is over; keep it only if both runs match."""
    templates = os.getenv("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
    stamp = datetime.now(timezone.utc).isoformat()
    warnings: list[str] = []
    for f in findings:
        meta = f.get("metadata") or {}
        if f.get("source") != "nuclei" or not meta.get("time_based") or not meta.get("template_id"):
            continue
        if not tool_available("nuclei"):
            return ["Nuclei is not installed; timing-based hits were not re-checked."]
        url = meta.get("input_url") or meta.get("url")
        cmd = ["nuclei", "-u", url, "-t", templates, "-id", str(meta["template_id"]), "-jsonl", "-silent", "-nc",
               "-duc", "-ni", "-sr", "-c", "1", "-rl", "5", "-timeout", "20", "-retries", "0"]
        if "/dast/" in str(meta.get("template_path") or "").replace("\\", "/"):
            cmd.append("-dast")
        hits, timed_out = 0, False
        for _ in range(2):
            code, out, _err = _run(cmd, timeout=_env_int("NUCLEI_RECHECK_SECONDS", 120))
            timed_out |= code == -9
            hits += 1 if _parse_nuclei(out) else 0
        record = {"tool": "nuclei", "attempts": 2, "at": stamp}
        if hits == 2:
            f["confidence"] = max(float(f.get("confidence") or 0), 0.95)
            meta["confirmation"] = {"status": "confirmed", **record,
                                    "detail": "The timing-based check reproduced on two quiet, single-request re-runs."}
        elif hits == 0 and not timed_out:
            f["confidence"] = min(float(f.get("confidence") or 0.5), 0.3)
            meta["confirmation"] = {"status": "not_reproduced", **record,
                                    "detail": "The delay did not recur on two quiet re-runs; the first hit was most likely the target "
                                              "responding slowly under scan load."}
        else:
            meta["confirmation"] = {"status": "inconclusive", **record,
                                    "detail": f"Reproduced on {hits} of 2 quiet re-runs."}
        f["metadata"] = meta
    return warnings


# ---------------------------------------------------------------------------
# Merge: one finding per issue per host, across engines
# ---------------------------------------------------------------------------

_CANON: list[tuple[str, re.Pattern]] = [
    ("hdr:csp", re.compile(r"content[- ]security[- ]policy|\bcsp\b", re.I)),
    ("hdr:xfo", re.compile(r"clickjacking|x-frame-options|anti-clickjacking", re.I)),
    ("hdr:xcto", re.compile(r"x-content-type-options|mime[- ]sniff", re.I)),
    ("hdr:hsts", re.compile(r"strict[- ]transport|\bhsts\b", re.I)),
    ("hdr:referrer", re.compile(r"referrer[- ]policy", re.I)),
    ("hdr:permissions", re.compile(r"permissions[- ]policy", re.I)),
    ("info:server-version", re.compile(r"server (leaks )?version|version disclosure|x-powered-by|server header|server technology information disclosure", re.I)),
    ("cookie:httponly", re.compile(r"httponly", re.I)),
    ("cookie:secure", re.compile(r"cookie.*secure flag|secure attribute", re.I)),
    ("cookie:samesite", re.compile(r"samesite", re.I)),
    ("cors", re.compile(r"\bcors\b|cross[- ]domain misconfiguration|access-control-allow-origin", re.I)),
    ("dirlist", re.compile(r"directory (listing|browsing|index)", re.I)),
    ("exposure:git", re.compile(r"\.git\b|git (config|repository)", re.I)),
    ("exposure:env", re.compile(r"\.env\b", re.I)),
    ("exposure:swagger", re.compile(r"swagger|openapi", re.I)),
    ("tls:tls1.0", re.compile(r"tls 1\.0|tlsv1\.0|\btls1\b", re.I)),
    ("tls:tls1.1", re.compile(r"tls 1\.1|tlsv1\.1|tls1_1", re.I)),
    ("tls:cert", re.compile(r"certificate (expired|not trusted|name mismatch)|self[- ]signed", re.I)),
]


def merge_key(f: dict[str, Any]) -> str:
    meta = f.get("metadata") or {}
    host = meta.get("host") or _host_port(meta.get("url") or "")[0] or "unknown"
    port = f.get("port") or ""
    cwe = str(meta.get("cwe_id") or "")
    if cwe in {"79", "89", "22", "918", "601", "611", "78", "94"} and meta.get("param"):
        return f"{host}:{port}|cwe-{cwe}|{str(meta.get('param')).lower()}"
    cves = sorted({c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,7}", str(f.get("cve_id") or ""), re.I)})
    if cves:
        return f"{host}:{port}|{','.join(cves)}"
    text = " ".join(str(x) for x in (f.get("title"), meta.get("template_id"), meta.get("testssl_id")) if x)
    for key, pattern in _CANON:
        if pattern.search(text):
            return f"{host}:{port}|{key}"
    # Drop a trailing "(matcher-name)" suffix, but never an endpoint such as "(/api/Feedbacks)":
    # findings about different endpoints are different issues.
    title = re.sub(r"\s+\([^/()]*\)$", "", str(f.get("title") or "")).strip().lower()
    return f"{host}:{port}|{title}"


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine the same issue from several engines into one finding. Agreement raises confidence."""
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        groups.setdefault(merge_key(f), []).append(f)

    merged = []
    for key, items in groups.items():
        # Primary record: most severe, then most confident.
        items.sort(key=lambda f: (order.get(f.get("severity"), 9), -float(f.get("confidence") or 0)))
        primary = dict(items[0])
        meta = dict(primary.get("metadata") or {})
        sources = []
        urls = list(meta.get("affected_urls") or ([meta["url"]] if meta.get("url") else []))
        others = []
        for f in items:
            fm = f.get("metadata") or {}
            if f.get("source") and f.get("source") not in sources:
                sources.append(f.get("source"))
            for u in (fm.get("affected_urls") or [fm.get("url")]):
                if u and u not in urls and len(urls) < 50:
                    urls.append(u)
            if f is not items[0]:
                others.append({"source": f.get("source"), "title": f.get("title"), "evidence": str(f.get("evidence") or "")[:400]})
                if not primary.get("cve_id") and f.get("cve_id"):
                    primary["cve_id"] = f["cve_id"]
                if fm.get("confirmation") and not meta.get("confirmation"):
                    meta["confirmation"] = fm["confirmation"]
        meta.update({"merge_key": key, "sources": sources, "affected_urls": urls})
        if others:
            meta["merged_evidence"] = others
        status = (meta.get("confirmation") or {}).get("status")
        if len(sources) >= 2 and status != "not_reproduced":
            # Independent engines agreeing is strong evidence.
            primary["confidence"] = min(0.99, max(float(primary.get("confidence") or 0), 0.75) + 0.1)
            meta["corroborated"] = True
        primary["metadata"] = meta
        merged.append(primary)
    return merged
