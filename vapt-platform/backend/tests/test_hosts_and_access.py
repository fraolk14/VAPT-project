import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from fastapi import HTTPException

from app.routers import iam
from app.services.ai import MODEL_ONLY_ANALYSES, ai_status
from app.services.hosts import _is_range, host_key


class HostKeyTests(unittest.TestCase):
    def test_targets_normalise_to_host(self):
        self.assertEqual(host_key("http://juice-shop:3000/#/login"), "juice-shop")
        self.assertEqual(host_key("192.168.10.25"), "192.168.10.25")
        self.assertEqual(host_key("HTTPS://App.Example.com/path"), "app.example.com")
        self.assertEqual(host_key(""), "")

    def test_ranges_are_not_hosts(self):
        self.assertTrue(_is_range("192.168.1.0/24"))
        self.assertFalse(_is_range("192.168.1.5/32"))
        self.assertFalse(_is_range("192.168.1.5"))


class AdminGuardTests(unittest.TestCase):
    def _user(self, uid, role="admin", active=True):
        return SimpleNamespace(id=uid, role=role, is_active=active, username=uid)

    def test_cannot_remove_own_admin_rights(self):
        me = self._user("a")
        with self.assertRaises(HTTPException):
            iam._guard_admin_change(MagicMock(), me, me, removes_admin=True, action="deactivate")

    def test_cannot_remove_last_admin(self):
        me, other = self._user("a"), self._user("b")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [other]
        with self.assertRaises(HTTPException):
            iam._guard_admin_change(db, me, other, removes_admin=True, action="delete")

    def test_can_remove_admin_when_another_remains(self):
        me, other = self._user("a"), self._user("b")
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [me, other]
        iam._guard_admin_change(db, me, other, removes_admin=True, action="delete")

    def test_short_password_rejected(self):
        with self.assertRaises(HTTPException):
            iam._check_password("short")


class AiStatusTests(unittest.TestCase):
    def test_without_model_guesswork_analyses_are_not_offered(self):
        status = ai_status()
        if not status["available"]:
            self.assertIn(status["status"], {"not_configured", "model_unavailable"})
            self.assertTrue({"risk-score", "false-positive", "threat-intel"} <= MODEL_ONLY_ANALYSES)


if __name__ == "__main__":
    unittest.main()
