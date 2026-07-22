import hashlib
import plistlib
import re
import zipfile
from pathlib import Path
from typing import Any
from uuid import uuid4


MOBILE_UPLOADS_DIR = Path(__file__).resolve().parents[1] / "data" / "uploads" / "mobile"
TEXT_EXTENSIONS = {
    ".txt",
    ".json",
    ".xml",
    ".plist",
    ".properties",
    ".yml",
    ".yaml",
    ".conf",
    ".config",
    ".js",
    ".ts",
    ".kt",
    ".java",
    ".swift",
    ".m",
    ".mm",
    ".smali",
    ".html",
}
SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api|auth|client|access|secret|token|password)[\w-]{0,12}\s*[:=]\s*['\"]?([A-Za-z0-9_+/=-]{16,})"),
]
HTTP_URL_PATTERN = re.compile(r"http://[A-Za-z0-9._/:?=&%#-]+", re.IGNORECASE)
ENVIRONMENT_PATTERN = re.compile(r"(?i)(staging|sandbox|dev(elopment)?|test|localhost|10\.|172\.(1[6-9]|2\d|3[0-1])\.|192\.168\.)")


def ensure_mobile_storage() -> None:
    MOBILE_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def persist_mobile_upload(file_name: str, content: bytes) -> dict[str, Any]:
    ensure_mobile_storage()
    suffix = Path(file_name or "mobile-binary").suffix.lower()
    stored_name = f"{uuid4().hex}{suffix}"
    path = MOBILE_UPLOADS_DIR / stored_name
    path.write_bytes(content)
    sha256 = hashlib.sha256(content).hexdigest()
    platform = "android" if suffix in {".apk", ".aab"} else "ios" if suffix == ".ipa" else "mobile"
    return {
        "original_file_name": file_name,
        "stored_file_path": str(path),
        "stored_file_name": stored_name,
        "sha256": sha256,
        "file_size": len(content),
        "platform": platform,
    }


def _finding(
    *,
    title: str,
    severity: str,
    cvss: float,
    evidence: str,
    remediation: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "title": title,
        "category": "mobile",
        "source": "mobsf",
        "port": 0,
        "protocol": "file",
        "service": "mobile-binary",
        "state": "open",
        "cve_id": None,
        "cvss_score": cvss,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
        "compliance_map": ["MASVS", "OWASP MSTG"],
        "metadata": metadata,
    }


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except Exception:
            continue
    return data.decode("utf-8", errors="ignore")


def _extract_text_matches(zf: zipfile.ZipFile) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for name in zf.namelist():
        path = Path(name)
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            raw = zf.read(name)
        except Exception:
            continue
        if len(raw) > 1_500_000:
            continue
        matches.append((name, _decode_text(raw)))
    return matches


def _ios_plist_metadata(zf: zipfile.ZipFile) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    plist_candidates = [name for name in zf.namelist() if name.endswith("Info.plist")]
    for name in plist_candidates:
        try:
            payload = plistlib.loads(zf.read(name))
        except Exception:
            continue
        metadata["bundle_id"] = payload.get("CFBundleIdentifier") or metadata.get("bundle_id")
        metadata["app_name"] = payload.get("CFBundleDisplayName") or payload.get("CFBundleName") or metadata.get("app_name")
        ats = payload.get("NSAppTransportSecurity") or {}
        metadata["ats_allows_arbitrary_loads"] = bool(ats.get("NSAllowsArbitraryLoads"))
        break
    return metadata


def local_mobile_static_analysis(file_path: str, file_name: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = Path(file_path)
    findings: list[dict[str, Any]] = []
    metadata: dict[str, Any] = {
        "analysis_engine": "local-static-mobile",
        "original_file_name": file_name,
        "platform": "android" if path.suffix.lower() in {".apk", ".aab"} else "ios" if path.suffix.lower() == ".ipa" else "mobile",
    }
    titles: set[str] = set()

    if not path.exists():
        return (
            [
                _finding(
                    title="Uploaded mobile binary is unavailable",
                    severity="high",
                    cvss=7.5,
                    evidence=f"The expected mobile binary path {file_path} does not exist at analysis time.",
                    remediation="Re-upload the APK, IPA, or AAB and re-run the mobile assessment.",
                    metadata=metadata,
                )
            ],
            metadata,
        )

    try:
        with zipfile.ZipFile(path) as zf:
            metadata.update(_ios_plist_metadata(zf))
            text_blobs = _extract_text_matches(zf)
            bundle_entries = zf.namelist()

            sensitive_files = [name for name in bundle_entries if Path(name).suffix.lower() in {".pem", ".key", ".p12", ".jks", ".keystore"}]
            if sensitive_files:
                title = "Sensitive key material bundled inside mobile package"
                titles.add(title)
                findings.append(
                    _finding(
                        title=title,
                        severity="critical",
                        cvss=9.1,
                        evidence=f"Bundled cryptographic material found in archive entries: {', '.join(sensitive_files[:5])}.",
                        remediation="Remove private keys, keystores, and signing material from the mobile package. Store secrets and keys in secure build-time or server-side controls only.",
                        metadata={**metadata, "files": sensitive_files[:10]},
                    )
                )

            cleartext_hits: list[str] = []
            secret_hits: list[str] = []
            env_hits: list[str] = []
            for name, text in text_blobs:
                if len(cleartext_hits) < 8:
                    cleartext_hits.extend([f"{name}: {match}" for match in HTTP_URL_PATTERN.findall(text) if "127.0.0.1" not in match][:3])
                if len(env_hits) < 8 and ENVIRONMENT_PATTERN.search(text):
                    env_hits.append(name)
                for pattern in SECRET_PATTERNS:
                    pattern_matches = pattern.findall(text)
                    if not pattern_matches:
                        continue
                    if isinstance(pattern_matches[0], tuple):
                        values = [match[1] for match in pattern_matches if len(match) > 1]
                    else:
                        values = pattern_matches
                    for value in values[:3]:
                        if len(secret_hits) < 8:
                            secret_hits.append(f"{name}: {value[:8]}...")

            if cleartext_hits:
                title = "Cleartext HTTP endpoints referenced by mobile application"
                titles.add(title)
                findings.append(
                    _finding(
                        title=title,
                        severity="high",
                        cvss=8.0,
                        evidence="Potential cleartext endpoints found in packaged resources or code: " + "; ".join(cleartext_hits[:6]),
                        remediation="Remove cleartext endpoints where possible and enforce HTTPS/TLS for all remote communications. For Android, combine this with a strict network security configuration.",
                        metadata={**metadata, "cleartext_endpoints": cleartext_hits[:10]},
                    )
                )

            if secret_hits:
                title = "Hardcoded secret material detected in mobile package"
                titles.add(title)
                findings.append(
                    _finding(
                        title=title,
                        severity="critical",
                        cvss=9.0,
                        evidence="Secret-like values were detected in packaged resources or code: " + "; ".join(secret_hits[:6]),
                        remediation="Remove hardcoded secrets from the application package. Rotate exposed credentials and move secret retrieval to a protected backend or mobile-safe secret delivery design.",
                        metadata={**metadata, "secret_hits": secret_hits[:10]},
                    )
                )

            if env_hits:
                title = "Non-production or internal environment indicators found in mobile package"
                titles.add(title)
                findings.append(
                    _finding(
                        title=title,
                        severity="medium",
                        cvss=5.8,
                        evidence="Environment-specific strings such as staging, sandbox, localhost, or RFC1918 references were found in: " + ", ".join(env_hits[:8]),
                        remediation="Review whether development, staging, sandbox, or internal infrastructure references should be removed from production mobile builds.",
                        metadata={**metadata, "environment_hits": env_hits[:12]},
                    )
                )

            if metadata.get("platform") == "ios" and metadata.get("ats_allows_arbitrary_loads"):
                title = "iOS App Transport Security allows arbitrary loads"
                if title not in titles:
                    findings.append(
                        _finding(
                            title=title,
                            severity="high",
                            cvss=7.4,
                            evidence="The iOS Info.plist indicates NSAllowsArbitraryLoads is enabled, which can weaken transport protections.",
                            remediation="Disable NSAllowsArbitraryLoads and define only narrowly scoped ATS exceptions where they are technically required and approved.",
                            metadata=metadata,
                        )
                    )
                    titles.add(title)
    except zipfile.BadZipFile:
        findings.append(
            _finding(
                title="Mobile binary archive could not be unpacked for local analysis",
                severity="medium",
                cvss=5.0,
                evidence=f"The uploaded file {file_name} is not a readable archive for local fallback analysis.",
                remediation="Confirm the uploaded binary is a valid APK, AAB, or IPA and re-run the mobile assessment.",
                metadata=metadata,
            )
        )

    if not findings:
        findings.append(
            _finding(
                title="No high-confidence mobile weaknesses detected by local static fallback",
                severity="info",
                cvss=0.0,
                evidence="The local fallback analyzer did not find high-confidence secrets, cleartext endpoints, ATS weaknesses, or sensitive key material in the uploaded package.",
                remediation="Run MobSF-backed analysis for deeper mobile coverage such as manifest, binary, certificate, and code rule evaluation when the mobile engine is available.",
                metadata=metadata,
            )
        )

    return findings, metadata
