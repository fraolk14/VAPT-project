import unittest

from app.services.software_posture import is_system_component, policy_class, product_key


class ProductKeyTests(unittest.TestCase):
    def test_versions_and_architecture_are_stripped(self):
        cases = {
            "Wireshark 4.4.1 x64": "wireshark",
            "7-Zip 23.01 (x64)": "7-zip",
            "PuTTY release 0.83 (64-bit)": "putty",
            "Go Programming Language amd64 go1.26.5": "go programming language",
            "Eclipse Temurin JDK with Hotspot 21.0.11+10 (x64)": "eclipse temurin jdk with hotspot",
            "Microsoft Visual Studio Code (User)": "microsoft visual studio code",
            "Notepad++ (64-bit x64)": "notepad++",
            "draw.io 24.7.5": "draw.io",
        }
        for name, key in cases.items():
            self.assertEqual(product_key(name), key, name)

    def test_versions_of_one_product_share_a_key(self):
        self.assertEqual(product_key("Telegram Desktop 7.0.9"), product_key("Telegram Desktop 7.1.3"))


class PolicyTests(unittest.TestCase):
    def test_policy_classes(self):
        self.assertEqual(policy_class("AnyDesk")[0], "remote-access")
        self.assertEqual(policy_class("Binance 1.54.5")[0], "crypto")
        self.assertEqual(policy_class("Wireshark 4.4.1 x64")[0], "network-tools")
        self.assertIsNone(policy_class("7-Zip 23.01 (x64)"))

    def test_system_components(self):
        self.assertTrue(is_system_component("Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030"))
        self.assertTrue(is_system_component("Windows Driver Package - Lenovo Monitor"))
        self.assertFalse(is_system_component("Google Chrome"))


if __name__ == "__main__":
    unittest.main()
