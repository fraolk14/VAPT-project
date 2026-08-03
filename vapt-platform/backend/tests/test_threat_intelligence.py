import os
import unittest
from unittest.mock import patch

from app.services.cve_lookup import lookup_cve_for_service
from app.services.threat_intelligence import _infer_company_name, fetch_abusech_events


class ThreatIntelligenceTests(unittest.TestCase):
    def test_lookup_cve_for_service_uses_live_nvd_data_when_available(self):
        with patch("app.services.cve_lookup.requests.get") as mock_get:
            mock_get.return_value.raise_for_status.return_value = None
            mock_get.return_value.ok = True
            mock_get.return_value.json.return_value = {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-12345",
                            "metrics": {
                                "cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}],
                            },
                        }
                    }
                ]
            }

            result = lookup_cve_for_service("nginx")

        self.assertEqual(result["cve_id"], "CVE-2024-12345")
        self.assertEqual(result["cvss_score"], 8.1)
        self.assertEqual(result["severity"], "high")

    def test_infer_company_name_prefers_live_company_lookup(self):
        with patch("app.services.threat_intelligence.requests.get") as mock_get:
            mock_get.return_value.raise_for_status.return_value = None
            mock_get.return_value.json.return_value = {
                "results": {
                    "companies": [{"company": {"name": "Example Corp"}}]
                }
            }

            company_name = _infer_company_name("api.example.com", "United States")

        self.assertEqual(company_name, "Example Corp")

    def test_fetch_abusech_events_uses_configured_key_and_endpoint(self):
        os.environ["ABUSECH_API_KEY"] = "test-key"
        os.environ["ABUSECH_FEED_URL"] = "https://example.test/feed"
        os.environ["ABUSECH_VERIFY_SSL"] = "false"

        with patch("app.services.threat_intelligence.requests.post") as mock_post:
            mock_post.return_value.raise_for_status.return_value = None
            mock_post.return_value.json.return_value = {"data": [{"id": "1", "name": "Test event"}]}

            status, events = fetch_abusech_events(limit=1)

        self.assertEqual(status, "connected")
        self.assertEqual(events[0]["name"], "Test event")
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args.kwargs["headers"]["Authorization"], "test-key")
        self.assertEqual(call_args.kwargs["headers"]["Auth-Key"], "test-key")
        self.assertFalse(call_args.kwargs["verify"])
        self.assertEqual(call_args.args[0], "https://example.test/feed")


if __name__ == "__main__":
    unittest.main()
