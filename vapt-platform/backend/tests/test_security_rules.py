import unittest
from types import SimpleNamespace

from fastapi import HTTPException

from app.services.network_assessment import SOFT_404_PROBE_PATH, _is_real_page
from app.services.security import enforce_roles, normalize_role


def _user(role):
    return SimpleNamespace(role=role)


class RoleNormalizationTests(unittest.TestCase):
    def test_iam_role_names_map_to_platform_roles(self):
        self.assertEqual(normalize_role("Admin"), "admin")
        self.assertEqual(normalize_role("SecurityEngineer"), "analyst")
        self.assertEqual(normalize_role("Auditor"), "auditor")
        self.assertEqual(normalize_role("Viewer"), "viewer")

    def test_unknown_roles_get_least_privilege(self):
        self.assertEqual(normalize_role("superuser"), "viewer")
        self.assertEqual(normalize_role(None), "viewer")

    def test_iam_admin_passes_admin_check(self):
        enforce_roles(_user("Admin"), "admin")

    def test_auditor_can_read_but_not_scan(self):
        enforce_roles(_user("Auditor"), "admin", "analyst", "viewer")
        with self.assertRaises(HTTPException):
            enforce_roles(_user("Auditor"), "admin", "analyst")

    def test_viewer_cannot_do_admin_actions(self):
        with self.assertRaises(HTTPException):
            enforce_roles(_user("viewer"), "admin")


class SoftNotFoundTests(unittest.TestCase):
    SPA = "<!doctype html><html><head><title>App</title></head><body><app-root></app-root></body></html>"

    def _probe(self, path, status, body):
        return {"path": path, "status_line": f"HTTP/1.1 {status} OK", "body_excerpt": body}

    def test_catch_all_spa_page_is_not_a_real_page(self):
        probes = [
            self._probe("/actuator/health", 200, self.SPA),
            self._probe(SOFT_404_PROBE_PATH, 200, self.SPA),
        ]
        self.assertFalse(_is_real_page(probes[0], probes))

    def test_distinct_page_is_real_when_random_path_is_404(self):
        probes = [
            self._probe("/actuator/health", 200, '{"status":"UP"}'),
            {"path": SOFT_404_PROBE_PATH, "status_line": "HTTP/1.1 404 Not Found", "body_excerpt": "nope"},
        ]
        self.assertTrue(_is_real_page(probes[0], probes))


class MobSFReportParsingTests(unittest.TestCase):
    def test_v4_report_sections_become_findings(self):
        from app.services.integrations import MobSFClient

        report = {
            "package_name": "com.example.app",
            "appsec": {
                "high": [{"title": "App can be installed on vulnerable Android versions", "description": "minSdk 21", "section": "manifest"}],
                "warning": [{"title": "Duplicate of code finding", "description": "x", "section": "code"}],
                "hotspot": [],
            },
            "code_analysis": {
                "findings": {
                    "android_logging": {
                        "files": {"com/example/Log.java": "12,30"},
                        "metadata": {"severity": "info", "description": "The App logs information."},
                    },
                    "android_insecure_random": {
                        "files": {"com/example/Rand.java": "8"},
                        "metadata": {"severity": "warning", "cvss": 7.5, "cwe": "CWE-330", "description": "The App uses an insecure Random Number Generator."},
                    },
                },
                "summary": {},
            },
        }
        findings = MobSFClient().normalize_report(report)
        titles = [f["title"] for f in findings]
        self.assertIn("App can be installed on vulnerable Android versions", titles)
        self.assertNotIn("Duplicate of code finding", titles)
        rng = next(f for f in findings if "Random" in f["title"])
        self.assertEqual(rng["severity"], "medium")
        self.assertEqual(rng["cvss_score"], 7.5)
        self.assertIn("com/example/Rand.java", rng["evidence"])
        self.assertFalse(any("logs information" in f["evidence"] for f in findings))


class NoiseReductionTests(unittest.TestCase):
    def test_sensitive_fields_are_detected_by_json_key(self):
        from app.services.web_assessment import _sensitive_json_fields

        self.assertEqual(_sensitive_json_fields('{"data":[{"id":1,"email":"a@b.c","passwordHash":"x"}]}'), ["email", "passwordHash"])
        # Words inside values (a product description mentioning "user" or "key") are not sensitive fields.
        self.assertEqual(_sensitive_json_fields('{"data":[{"name":"Apple","description":"key lime for every user"}]}'), [])

    def test_zap_alerts_are_grouped_per_issue(self):
        from app.services.integrations import ZAPClient

        raw = [
            {"alert": "Timestamp Disclosure - Unix", "risk": "Low", "riskcode": "1", "url": f"http://app:3000/p{i}", "pluginId": "10096"}
            for i in range(30)
        ] + [{"alert": "SQL Injection", "risk": "High", "riskcode": "3", "url": "http://app:3000/search?q=1", "param": "q", "pluginId": "40018"}]
        findings = ZAPClient().normalize_results(raw)
        self.assertEqual(len(findings), 2)
        ts = next(f for f in findings if f["title"].startswith("Timestamp"))
        self.assertEqual(ts["metadata"]["occurrences"], 30)
        self.assertIn("Found on 30 URLs", ts["evidence"])


if __name__ == "__main__":
    unittest.main()
