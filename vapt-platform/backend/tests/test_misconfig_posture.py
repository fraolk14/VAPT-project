import unittest
from types import SimpleNamespace

from app.services.misconfig_posture import _issue_title, classify
from app.services.misconfig_scanner import FABRICATED_MISCONFIGS


def _f(title, category="network", source="socket", cve=None, severity="medium"):
    return SimpleNamespace(title=title, category=category, source=source, cve_id=cve, severity=severity)


class ClassifyTests(unittest.TestCase):
    def test_families(self):
        self.assertEqual(classify(_f("LLMNR Protocol Enabled", "Misconfiguration", "endpoint-agent", "CIS 18.9.30.2")), "os-hardening")
        self.assertEqual(classify(_f("Redis responds without authentication challenge")), "auth")
        self.assertEqual(classify(_f("Web response missing Content-Security-Policy")), "headers")
        self.assertEqual(classify(_f("Cleartext HTTP service exposed")), "transport")
        self.assertEqual(classify(_f("Exposed postgresql service")), "exposed-services")
        self.assertEqual(classify(_f("Exposed Git Version Control Repository", "web", "zap")), "disclosure")

    def test_non_configuration_findings_are_excluded(self):
        self.assertIsNone(classify(_f("SQL Injection in login form", "web", "zap", severity="high")))
        self.assertIsNone(classify(_f("AnyDesk installed", "Shadow IT", "endpoint-agent")))
        self.assertIsNone(classify(_f("No exposed services detected during deep assessment", severity="info")))

    def test_engine_wording_is_merged(self):
        self.assertEqual(_issue_title("Exposed smb service"), "SMB service exposed")
        self.assertEqual(_issue_title("Exposed postgresql service"), "PostgreSQL service exposed")

    def test_fabricated_catalogue_covers_old_engine_output(self):
        self.assertIn(("Nmap", "Cisco IOS XE Web UI Unauthenticated Remote Code Execution"), FABRICATED_MISCONFIGS)
        self.assertIn(("Lynis", "Outdated Kernel Version Vulnerable to Privilege Escalation"), FABRICATED_MISCONFIGS)


if __name__ == "__main__":
    unittest.main()
