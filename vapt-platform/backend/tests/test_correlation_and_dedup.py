import unittest
from unittest.mock import patch

from app.services.cis_hardening import compliance_tags
from app.services.orchestrator import _finding_deduplication_key
from app.services.vulnerability_correlation import correlate_finding


class CorrelationAndDedupTests(unittest.TestCase):
    def test_deduplication_key_is_stable_for_rescans(self):
        first = {
            "title": "Apache HTTP Server Vulnerability",
            "service": "apache",
            "port": 80,
            "protocol": "tcp",
            "category": "web",
            "source": "openvas",
            "state": "open",
            "evidence": "Version disclosure indicates 2.4.49.",
        }
        second = {
            "title": "Apache HTTP Server Vulnerability",
            "service": "apache",
            "port": 80,
            "protocol": "tcp",
            "category": "web",
            "source": "openvas",
            "state": "open",
            "evidence": "Version disclosure indicates 2.4.49. Repeated on rescan.",
        }

        self.assertEqual(
            _finding_deduplication_key(first, asset_key="app.internal"),
            _finding_deduplication_key(second, asset_key="app.internal"),
        )

    def test_correlate_finding_does_not_override_native_cvss_for_weak_fallbacks(self):
        item = {
            "title": "Possible server issue",
            "category": "web",
            "source": "openvas",
            "port": 80,
            "protocol": "tcp",
            "service": "apache",
            "state": "open",
            "cvss_score": 3.5,
            "severity": "medium",
            "confidence": 0.86,
            "evidence": "The service version appears to be 2.4.49.",
            "remediation": "Patch the service.",
            "metadata": {},
        }

        with patch("app.services.vulnerability_correlation.lookup_nvd", return_value={"cvss_score": 9.8, "summary": "test"}), patch(
            "app.services.vulnerability_correlation.lookup_osv", return_value={}
        ):
            correlated = correlate_finding(item, db=None)

        self.assertEqual(correlated["cvss_score"], 3.5)
        self.assertEqual(correlated["severity"], "medium")

    def test_compliance_tags_are_context_specific(self):
        tags = compliance_tags(
            os_family="linux",
            service="https",
            title="Weak TLS configuration",
            evidence="TLS 1.0 enabled",
        )

        self.assertIn("NIST SC-8", tags)
        self.assertIn("ISO A.8.24", tags)
        self.assertNotIn("NIST RA-5", tags)


if __name__ == "__main__":
    unittest.main()
