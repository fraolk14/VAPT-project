from collections import Counter
from typing import Any


def classify_shadow_it(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    services = Counter(event.get("service", "unknown") for event in events)
    discovered = []
    for service, volume in services.items():
        discovered.append(
            {
                "service": service,
                "volume": volume,
                "risk": "high" if service not in {"microsoft365", "google-workspace", "slack"} else "medium",
                "recommended_action": "Validate business owner and approve or block usage.",
            }
        )
    return discovered


def detect_unauthorized_software(
    installed_applications: list[str], approved_baseline: list[str]
) -> list[dict[str, str]]:
    baseline = {item.lower() for item in approved_baseline}
    findings = []
    for app in installed_applications:
        if app.lower() not in baseline:
            findings.append(
                {
                    "application": app,
                    "risk": "medium",
                    "reason": "Installed software is not present in the approved baseline.",
                }
            )
    return findings
