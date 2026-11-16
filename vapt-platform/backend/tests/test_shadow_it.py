import unittest
from types import SimpleNamespace

from app.services.shadow_it import classify_app, review_state


class ShadowAppTests(unittest.TestCase):
    def test_agent_titles_map_to_category_and_app(self):
        self.assertEqual(classify_app("Unauthorized Remote Access Tool Detected: AnyDesk"), ("remote-access", "AnyDesk"))
        self.assertEqual(classify_app("AnyDesk Remote Control"), ("remote-access", "AnyDesk"))
        self.assertEqual(classify_app("Unsanctioned Personal Cloud Storage Client Detected: MEGAsync"), ("cloud-storage", "MEGAsync"))
        self.assertEqual(classify_app("USB Mass Storage Devices Connected (1 Total Detected)"), ("removable-media", "USB mass storage"))
        self.assertEqual(classify_app("Google Chrome Extensions Detected (14 Installed)"), ("browser-extensions", "Chrome extensions"))

    def test_unknown_tool_keeps_its_name(self):
        self.assertEqual(classify_app("Unapproved Software Detected: FooTool"), ("other", "FooTool"))

    def test_review_state_reads_tag(self):
        self.assertEqual(review_state(SimpleNamespace(tags=["scan-discovered", "reviewed:sanctioned"])), "sanctioned")
        self.assertIsNone(review_state(SimpleNamespace(tags=["scan-discovered"])))


if __name__ == "__main__":
    unittest.main()
