import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services import web_pipeline as wp


NUCLEI_LINE = json.dumps({
    "template-id": "git-config",
    "info": {"name": "Git Config File Exposure", "severity": "medium",
             "classification": {"cwe-id": ["cwe-200"]}, "reference": ["https://example.org"]},
    "matched-at": "http://app.test:3000/.git/config",
    "host": "app.test:3000",
})
NUCLEI_CVE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {"name": "Log4Shell", "severity": "critical",
             "classification": {"cve-id": ["cve-2021-44228"], "cvss-score": 10.0}},
    "matched-at": "https://app.test/login",
})


def zap(title, cwe=None, param=None, severity="medium", conf=0.65, url="http://app.test:3000/a"):
    return {"title": title, "source": "zap", "severity": severity, "confidence": conf, "port": 3000,
            "metadata": {"url": url, "host": "app.test", "cwe_id": cwe, "param": param,
                         "instances": [{"url": url, "param": param, "method": "GET", "message_id": "7"}] if param else []}}


class ParseTests(unittest.TestCase):
    def test_nuclei_lines_become_findings(self):
        rows = wp._parse_nuclei(NUCLEI_LINE + "\nnot json\n" + NUCLEI_CVE)
        self.assertEqual(len(rows), 2)
        git, log4j = rows
        self.assertEqual(git["source"], "nuclei")
        self.assertEqual(git["port"], 3000)
        self.assertEqual(git["metadata"]["cwe_id"], "200")
        self.assertEqual(log4j["cve_id"], "CVE-2021-44228")
        self.assertEqual(log4j["severity"], "critical")
        self.assertEqual(log4j["port"], 443)


class NucleiCoverageTests(unittest.TestCase):
    def test_partial_run_is_reported(self):
        err = ('{"duration":"0:03:01","errors":"345","matched":"0","percent":"5","requests":"9249"}\n'
               '[WRN] something\n'
               '{"duration":"0:03:12","errors":"422","matched":"0","percent":"5","requests":"9276"}\n')
        self.assertEqual(wp._nuclei_percent(err), 5)
        self.assertIsNone(wp._nuclei_percent("no stats here"))
        gave_up = err + "[INF] Skipped app.test:80 from target list as found unresponsive permanently: Get ...\n"
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_run", return_value=(0, "", gave_up)):
            _findings, warnings = wp.run_nuclei("http://app.test", [])
        self.assertTrue(any("stopped early" in w and "5%" in w for w in warnings))

    def test_normal_finish_below_100_percent_is_not_a_warning(self):
        # Nuclei's total is an upper estimate; a clean run commonly ends near 90%.
        err = '{"percent":"90","requests":"23316"}\n'
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_run", return_value=(0, "", err)):
            _findings, warnings = wp.run_nuclei("http://app.test", [])
        self.assertEqual(warnings, [])


class MergeTests(unittest.TestCase):
    def test_same_header_issue_from_three_engines_becomes_one(self):
        items = [
            zap("Content Security Policy (CSP) Header Not Set"),
            {"title": "Web response missing Content-Security-Policy", "source": "web", "severity": "low", "confidence": 0.6,
             "port": 3000, "metadata": {"url": "http://app.test:3000/", "host": "app.test"}},
            {"title": "HTTP Missing Security Headers (content-security-policy)", "source": "nuclei", "severity": "info",
             "confidence": 0.9, "port": 3000, "metadata": {"url": "http://app.test:3000/", "host": "app.test",
                                                         "template_id": "http-missing-security-headers"}},
        ]
        merged = wp.merge_findings(items)
        self.assertEqual(len(merged), 1)
        m = merged[0]
        self.assertEqual(m["severity"], "medium")  # most severe kept
        self.assertEqual(set(m["metadata"]["sources"]), {"zap", "web", "nuclei"})
        self.assertTrue(m["metadata"]["corroborated"])
        self.assertEqual(len(m["metadata"]["merged_evidence"]), 2)

    def test_different_issues_stay_separate(self):
        merged = wp.merge_findings([zap("Content Security Policy (CSP) Header Not Set"), zap("Cookie No HttpOnly Flag")])
        self.assertEqual(len(merged), 2)

    def test_server_version_disclosure_from_zap_and_builtin_merge(self):
        a = zap('Server Leaks Version Information via "Server" HTTP Response Header Field', conf=0.9)
        b = {**zap("Web Server Technology Information Disclosure (Apache/2.4.25 (Debian))"), "source": "web"}
        merged = wp.merge_findings([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(set(merged[0]["metadata"]["sources"]), {"zap", "web"})

    def test_findings_about_different_endpoints_stay_separate(self):
        a = zap("Public API endpoint discovered (/api/Feedbacks)")
        b = zap("Public API endpoint discovered (/api/Quantitys)")
        self.assertEqual(len(wp.merge_findings([a, b])), 2)

    def test_injections_merge_by_parameter_not_title(self):
        a = zap("Cross Site Scripting (Reflected)", cwe="79", param="q")
        b = {**zap("Reflected XSS", cwe="79", param="q"), "source": "nuclei"}
        c = zap("Cross Site Scripting (Reflected)", cwe="79", param="id")
        self.assertEqual(len(wp.merge_findings([a, b, c])), 2)

    def test_unreproduced_finding_is_not_boosted(self):
        a = zap("SQL Injection", cwe="89", param="id", conf=0.35)
        a["metadata"]["confirmation"] = {"status": "not_reproduced"}
        b = {**zap("SQL Injection", cwe="89", param="id", conf=0.5), "source": "nuclei"}
        merged = wp.merge_findings([a, b])
        self.assertNotIn("corroborated", merged[0]["metadata"])


class ConfirmTests(unittest.TestCase):
    def test_confirmed_raises_and_unreproduced_lowers_confidence(self):
        sqli = zap("SQL Injection", cwe="89", param="id", conf=0.65)
        xss = zap("Cross Site Scripting (Reflected)", cwe="79", param="q", conf=0.65)
        other = zap("Cookie No HttpOnly Flag")
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_confirm_sqli", return_value=(True, "sqlmap confirmed")), \
             patch.object(wp, "_confirm_xss", return_value=(False, "no verified payload")):
            wp.confirm_injections([sqli, xss, other], zap_client=object())
        self.assertEqual(sqli["metadata"]["confirmation"]["status"], "confirmed")
        self.assertGreaterEqual(sqli["confidence"], 0.97)
        self.assertEqual(xss["metadata"]["confirmation"]["status"], "not_reproduced")
        self.assertLessEqual(xss["confidence"], 0.35)
        self.assertNotIn("confirmation", other["metadata"])

    def test_timeout_is_inconclusive_and_keeps_confidence(self):
        sqli = zap("SQL Injection", cwe="89", param="id", conf=0.65)
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_confirm_sqli", return_value=(None, "sqlmap timed out")):
            wp.confirm_injections([sqli], zap_client=object())
        self.assertEqual(sqli["metadata"]["confirmation"]["status"], "inconclusive")
        self.assertEqual(sqli["confidence"], 0.65)

    def test_dalfox_v3_report_is_parsed(self):
        report = {"findings": [{"type": "V", "param": "q", "inject_type": "inHTML", "location": "Query",
                                "payload": "<svg onload=alert(1)>"}],
                  "meta": {"incomplete": False, "failed_requests": 0, "total_requests": 21}}
        clean = {"findings": [], "meta": {"incomplete": False, "failed_requests": 0, "total_requests": 542}}
        partial = {"findings": [], "meta": {"incomplete": True, "failed_requests": 3, "total_requests": 90}}
        inst = {"url": "http://app.test/s?q=1", "param": "q", "method": "GET"}

        def fake_run(report_body):
            def _r(cmd, timeout, cwd=None):
                Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(report_body), encoding="utf-8")
                return 0, "", ""
            return _r

        for body, expected in ((report, True), (clean, False), (partial, None)):
            with tempfile.TemporaryDirectory() as tmp, \
                 patch.object(wp, "_zap_raw_request", return_value=None), \
                 patch.object(wp, "_run", side_effect=fake_run(body)):
                self.assertIs(wp._confirm_xss(object(), inst, tmp)[0], expected)

    def test_sqlmap_per_technique_proof_counts_even_if_run_later_times_out(self):
        out = ("[INFO] GET parameter 'q' is 'SQLite >= 3.9 AND error-based - WHERE clause' injectable\n"
               "[CRITICAL] connection timed out to the target URL\n")
        inst = {"url": "http://app.test/s?q=1", "param": "q", "method": "GET"}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(wp, "_zap_raw_request", return_value=None), \
             patch.object(wp, "_run", return_value=(-9, out, "timed out")):
            ok, detail = wp._confirm_sqli(object(), inst, tmp)
        self.assertTrue(ok)
        self.assertIn("error-based", detail)

    def test_time_based_nuclei_hit_that_does_not_recur_is_flagged(self):
        line = json.dumps({"template-id": "unix-command-injection", "template-path": "/opt/t/dast/vulnerabilities/cmdi/unix.yaml",
                           "info": {"name": "Unix Command Injection - Generic Detection (time-based)", "severity": "high"},
                           "url": "http://app.test/r?to=x", "matched-at": "http://app.test/r?to=;sleep 5"})
        hit = wp._parse_nuclei(line)[0]
        self.assertTrue(hit["metadata"]["time_based"])
        self.assertEqual(hit["metadata"]["input_url"], "http://app.test/r?to=x")
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_run", return_value=(0, "", "")) as run:
            wp.reverify_time_based([hit])
        self.assertIn("-dast", run.call_args[0][0])
        self.assertEqual(hit["metadata"]["confirmation"]["status"], "not_reproduced")
        self.assertLessEqual(hit["confidence"], 0.3)

    def test_missing_tool_is_a_warning_not_a_verdict(self):
        sqli = zap("SQL Injection", cwe="89", param="id")
        with patch.object(wp, "tool_available", return_value=False):
            warnings = wp.confirm_injections([sqli], zap_client=object())
        self.assertTrue(warnings)
        self.assertNotIn("confirmation", sqli["metadata"])


if __name__ == "__main__":
    unittest.main()
