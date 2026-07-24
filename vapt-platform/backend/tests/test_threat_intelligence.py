import os
import unittest
from unittest.mock import patch

from app.services.threat_intelligence import fetch_abusech_events


class ThreatIntelligenceTests(unittest.TestCase):
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
