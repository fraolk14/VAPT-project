from __future__ import annotations

import re


_TECHNIQUES: list[dict] = [
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "keywords": ["port", "service discovery", "network service", "banner", "nmap", "scan", "discovery"],
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "keywords": ["sql injection", "xss", "csrf", "clickjacking", "content-security-policy", "csp", "path traversal", "rce", "remote code"],
    },
    {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "keywords": ["secret", "credential", "password", "token", "hardcoded", "api key", "key leakage"],
    },
    {
        "id": "T1539",
        "name": "Steal Web Session Cookie",
        "keywords": ["cookie", "session", "httponly", "secure flag", "same-site", "samesite"],
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "keywords": ["directory listing", "index of /", "path", "filesystem", "enumeration"],
    },
]


def map_text_to_techniques(text: str | None, *, limit: int = 4) -> list[dict]:
    """Fast, local ATT&CK mapping. Keeps scans deterministic and avoids network lookups."""
    if not text:
        return []

    blob = re.sub(r"\s+", " ", str(text).lower())
    matches: list[dict] = []
    for technique in _TECHNIQUES:
        for keyword in technique["keywords"]:
            if keyword in blob:
                matches.append(
                    {
                        "technique_id": technique["id"],
                        "name": technique["name"],
                        "reason": f"Matched keyword '{keyword}'.",
                    }
                )
                break

    # de-duplicate while keeping order
    seen = set()
    unique = []
    for item in matches:
        if item["technique_id"] in seen:
            continue
        seen.add(item["technique_id"])
        unique.append(item)
    return unique[:limit]

