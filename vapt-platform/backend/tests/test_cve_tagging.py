import unittest

from app.services.cve_lookup import lookup_cve_for_service
from app.services.scan_correlator import _enrich_cves_for_finding, classify_cves, split_guessed_cves


class CveClassificationTests(unittest.TestCase):
    def test_open_port_only_gives_possible_cve_not_confirmed(self):
        confirmed, possible, cvss, severity = classify_cves("TCP connection to 10.0.0.5:445 succeeded. 445/tcp")
        self.assertEqual(confirmed, set())
        self.assertEqual(possible, {"CVE-2017-0144"})
        self.assertIsNone(severity)

    def test_vulnerable_version_is_confirmed(self):
        confirmed, _, _, severity = classify_cves("OpenSSH 7.2p2 Ubuntu 22/tcp")
        self.assertIn("CVE-2018-15473", confirmed)
        self.assertEqual(severity, "high")

    def test_patched_versions_are_not_tagged(self):
        for text in ("OpenSSH 9.6p1 22/tcp", "OpenSSH 8.9p1 22/tcp", "Apache httpd 2.4.58 80/tcp"):
            self.assertEqual(classify_cves(text)[0], set(), text)

    def test_enrichment_keeps_severity_for_guesses(self):
        finding = {"title": "Exposed rdp service", "service": "rdp", "port": 3389, "severity": "high", "cvss_score": 7.5}
        out = _enrich_cves_for_finding(finding)
        self.assertIsNone(out.get("cve_id"))
        self.assertEqual((out["severity"], out["cvss_score"]), ("high", 7.5))
        self.assertEqual(out["metadata"]["possible_cves"], ["CVE-2019-0708"])

    def test_service_lookup_no_longer_guesses(self):
        self.assertEqual(lookup_cve_for_service("nginx"), {"cve_id": None, "cvss_score": None, "severity": None})


class LegacyCleanupTests(unittest.TestCase):
    def test_guessed_cve_is_moved_out(self):
        self.assertEqual(split_guessed_cves("CVE-2017-0144", "TCP connection to 10.0.0.5:445 succeeded. 445/tcp"), (None, ["CVE-2017-0144"]))

    def test_cve_quoted_by_scanner_is_kept(self):
        evidence = "smb-vuln-ms17-010: VULNERABLE: Remote Code Execution (CVE-2017-0144)"
        self.assertEqual(split_guessed_cves("CVE-2017-0144", evidence), ("CVE-2017-0144", []))

    def test_non_cve_ids_and_confirmed_cves_are_kept(self):
        self.assertEqual(split_guessed_cves("CIS 2.3.1.5", "Windows Host"), ("CIS 2.3.1.5", []))
        self.assertEqual(split_guessed_cves("CVE-1999-0619", "telnet 23/tcp"), ("CVE-1999-0619", []))


if __name__ == "__main__":
    unittest.main()
