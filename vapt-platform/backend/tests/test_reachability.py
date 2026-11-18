import http.server
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

import requests

from app.services import web_pipeline as wp
from app.services.integrations import ZAPAPIError, ZAPClient


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ProbeTargetTests(unittest.TestCase):
    def test_unresolvable_host(self):
        ok, detail = wp.probe_target("https://does-not-exist.invalid/")
        self.assertFalse(ok)
        self.assertIn("resolve", detail)

    def test_refused_port(self):
        ok, detail = wp.probe_target(f"http://127.0.0.1:{_free_port()}/")
        self.assertFalse(ok)
        self.assertIn("refused", detail)

    def test_connection_that_never_answers(self):
        resolved = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 443))]
        with patch("socket.getaddrinfo", return_value=resolved), \
             patch("socket.create_connection", side_effect=socket.timeout("timed out")):
            ok, detail = wp.probe_target("https://example.test/", connect_timeout=1)
        self.assertFalse(ok)
        self.assertIn("could not connect", detail)
        self.assertIn("blocking", detail)

    def test_reachable_site(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            ok, detail = wp.probe_target(f"http://127.0.0.1:{server.server_port}/")
        finally:
            server.shutdown()
        self.assertTrue(ok, detail)
        self.assertIn("answered", detail)

    def test_wait_reports_a_target_that_never_answered(self):
        with patch.object(wp, "_first_byte_seconds", side_effect=requests.ConnectionError("down")), \
             patch("time.sleep"):
            ready, waited, answered = wp.wait_for_target("https://example.test/", max_wait=0)
        self.assertFalse(ready)
        self.assertFalse(answered)


class ZAPErrorTests(unittest.TestCase):
    def _http_error(self, code):
        resp = MagicMock()
        resp.json.return_value = {"code": code, "message": "URL Not Found in the Scan Tree"}
        err = requests.HTTPError("400 Client Error")
        err.response = resp
        return err

    def test_zap_rejection_is_reported_not_retried_without_key(self):
        bad = MagicMock()
        bad.raise_for_status.side_effect = self._http_error("url_not_found")
        with patch("app.services.integrations.requests.get", return_value=bad) as get:
            with self.assertRaises(ZAPAPIError) as ctx:
                ZAPClient()._request("ascan", "action", "scan", url="https://example.test/")
        self.assertEqual(ctx.exception.code, "url_not_found")
        self.assertEqual(get.call_count, 1)

    def test_network_retry_keeps_the_api_key(self):
        good = MagicMock()
        good.json.return_value = {"version": "2.17.0"}
        with patch.dict("os.environ", {"ZAP_API_KEY": "k123"}), \
             patch("app.services.integrations.requests.get",
                   side_effect=[requests.ConnectionError("blip"), good]) as get:
            ZAPClient()._request("core", "view", "version")
        retry = get.call_args_list[1]
        self.assertEqual(retry.kwargs["params"].get("apikey"), "k123")

    def test_active_scan_refusal_explains_empty_spider(self):
        client = ZAPClient()
        with patch.object(client, "_request", side_effect=ZAPAPIError("url_not_found", "URL Not Found in the Scan Tree")):
            meta = client.launch_active_scan("https://example.test/")
        self.assertIsNone(meta["active_scan_id"])
        self.assertIn("could not load any page", meta["active_scan_error"])


if __name__ == "__main__":
    unittest.main()
