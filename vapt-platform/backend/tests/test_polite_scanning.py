import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.services import orchestrator
from app.services import web_pipeline as wp


class PaceTests(unittest.TestCase):
    def test_default_is_polite_and_unknown_falls_back(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WEB_SCAN_PACE", None)
            self.assertEqual(wp.pace()["name"], "polite")
        with patch.dict(os.environ, {"WEB_SCAN_PACE": "warp"}):
            self.assertEqual(wp.pace()["name"], "polite")
        with patch.dict(os.environ, {"WEB_SCAN_PACE": "fast"}):
            self.assertEqual(wp.pace()["zap_threads"], 10)

    def test_polite_nuclei_runs_generic_checks_and_critical_cves_only(self):
        calls = []

        def fake_run(cmd, timeout, cwd=None):
            calls.append(cmd)
            return 0, "", ""

        with patch.dict(os.environ, {"WEB_SCAN_PACE": "polite"}), \
             patch.object(wp, "tool_available", return_value=True), patch.object(wp, "_run", side_effect=fake_run):
            wp.run_nuclei("http://app.test", [])
        self.assertEqual(len(calls), 2)
        generic, cves = calls
        self.assertIn("/opt/nuclei-templates/http/exposures", generic)
        self.assertEqual(generic[generic.index("-severity") + 1], "low,medium,high,critical")
        self.assertIn("/opt/nuclei-templates/http/cves", cves)
        self.assertEqual(cves[cves.index("-severity") + 1], "critical")
        self.assertEqual(generic[generic.index("-rl") + 1], "20")

    def test_dast_only_pass_skips_signature_checks(self):
        calls = []
        with patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_run", side_effect=lambda cmd, timeout, cwd=None: calls.append(cmd) or (0, "", "")):
            wp.run_nuclei("http://app.test", ["http://app.test/s?q=1", "http://app.test/about"], "balanced", signature=False)
        self.assertEqual(len(calls), 1)
        self.assertIn("-dast", calls[0])

    def test_normal_pace_runs_the_full_set_once(self):
        calls = []
        with patch.dict(os.environ, {"WEB_SCAN_PACE": "normal"}), \
             patch.object(wp, "tool_available", return_value=True), \
             patch.object(wp, "_run", side_effect=lambda cmd, timeout, cwd=None: calls.append(cmd) or (0, "", "")):
            wp.run_nuclei("http://app.test", [])
        self.assertEqual(len(calls), 1)
        self.assertIn("-pt", calls[0])


class SpeedTests(unittest.TestCase):
    def test_internal_targets_are_recognised(self):
        self.assertTrue(wp.is_internal_target("http://192.168.10.25:8080"))
        self.assertTrue(wp.is_internal_target("http://dvwa"))
        self.assertTrue(wp.is_internal_target("https://intranet.local/"))
        self.assertFalse(wp.is_internal_target("https://8.8.8.8/"))

    def test_auto_is_fast_inside_balanced_outside_and_env_overrides(self):
        with patch.dict(os.environ, {"WEB_SCAN_PACE": "auto"}):
            self.assertEqual(wp.resolve_pace("auto", "http://dvwa"), "fast")
            self.assertEqual(wp.resolve_pace("auto", "https://8.8.8.8/"), "balanced")
            self.assertEqual(wp.resolve_pace("polite", "http://dvwa"), "polite")
        with patch.dict(os.environ, {"WEB_SCAN_PACE": "polite"}):
            self.assertEqual(wp.resolve_pace("auto", "http://dvwa"), "polite")

    def test_nuclei_slows_down_while_running_alongside_zap(self):
        os.environ.pop("NUCLEI_RATE_LIMIT", None)
        self.assertEqual(wp._nuclei_rate("balanced", parallel=False), 25)
        self.assertEqual(wp._nuclei_rate("balanced", parallel=True), 15)
        self.assertEqual(wp._nuclei_rate("fast", parallel=True), 60)

    def test_background_job_returns_results_and_can_be_cancelled(self):
        with patch.object(wp, "run_nuclei", return_value=([{"title": "x"}], [])), \
             patch.object(wp, "run_testssl", return_value=([], ["tls skipped"])):
            wp.start_background_checks("scan-1", "http://app.test", [], "fast")
            res = wp.collect_background_checks("scan-1", timeout=10)
        self.assertEqual(len(res["nuclei"]), 1)
        self.assertEqual(res["tls_warnings"], ["tls skipped"])
        self.assertFalse(res["cancelled"])
        self.assertIsNone(wp.collect_background_checks("never-started", timeout=1))
        wp.cancel_background_checks("scan-2")
        wp._job.key = "scan-2"
        try:
            self.assertEqual(wp._run(["echo", "hi"], timeout=5)[0], -15)
        finally:
            wp._job.key = None
            wp._job_cancelled.discard("scan-2")


class BlockWatchTests(unittest.TestCase):
    def test_short_outage_does_not_abort(self):
        with patch.object(wp, "target_answers", return_value=False):
            meta, blocked = orchestrator._watch_for_block({}, "https://site.test")
        self.assertFalse(blocked)
        self.assertTrue(meta["unreachable_since"])

    def test_three_minutes_of_silence_aborts(self):
        since = (datetime.now(timezone.utc) - timedelta(seconds=orchestrator.BLOCK_ABORT_SECONDS + 5)).isoformat()
        with patch.object(wp, "target_answers", return_value=False):
            _meta, blocked = orchestrator._watch_for_block({"unreachable_since": since}, "https://site.test")
        self.assertTrue(blocked)

    def test_answer_resets_and_probes_are_rate_limited(self):
        since = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with patch.object(wp, "target_answers", return_value=True) as probe:
            meta, blocked = orchestrator._watch_for_block({"unreachable_since": since}, "https://site.test")
            self.assertFalse(blocked)
            self.assertIsNone(meta["unreachable_since"])
            orchestrator._watch_for_block(meta, "https://site.test")  # within a minute: no second probe
        self.assertEqual(probe.call_count, 1)

    def test_advice_names_the_scanner_ip(self):
        with patch.object(wp, "scanner_public_ip", return_value="203.0.113.7"):
            text = wp.blocked_advice("site.test")
        self.assertIn("203.0.113.7", text)
        self.assertIn("allow-list", text)


if __name__ == "__main__":
    unittest.main()
