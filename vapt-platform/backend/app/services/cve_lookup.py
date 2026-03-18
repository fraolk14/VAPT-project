import requests

def lookup_cve_for_service(service_name: str):
    """
    Lookup CVE info for a given service name.
    Currently uses a simple mock / placeholder logic.
    """

    # Temporary simple mapping (safe & stable)
    known_services = {
        "http": ("CVE-2023-44487", 7.5, "high"),
        "nginx": ("CVE-2023-44487", 7.5, "high"),
        "postgresql": ("CVE-2022-1552", 6.5, "medium"),
    }

    service_name = service_name.lower()

    if service_name in known_services:
        cve_id, cvss, severity = known_services[service_name]
        return {
            "cve_id": cve_id,
            "cvss_score": cvss,
            "severity": severity,
        }

    # No CVE found
    return {
        "cve_id": None,
        "cvss_score": None,
        "severity": None,
    }
