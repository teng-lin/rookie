"""Cookie server port is configurable for claimed-browser e2e."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("cookie_server.py")
SPEC = importlib.util.spec_from_file_location("cookie_server", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVER)

CLAIMED_PATH = Path(__file__).with_name("run_hosted_claimed_e2e.py")
CLAIMED_SPEC = importlib.util.spec_from_file_location(
    "run_hosted_claimed_e2e", CLAIMED_PATH
)
assert CLAIMED_SPEC is not None and CLAIMED_SPEC.loader is not None
CLAIMED = importlib.util.module_from_spec(CLAIMED_SPEC)
CLAIMED_SPEC.loader.exec_module(CLAIMED)


class CookieServerTests(unittest.TestCase):
    def test_default_port_is_8765(self) -> None:
        with mock.patch.dict(SERVER.os.environ, {}, clear=False):
            SERVER.os.environ.pop("ROOKIE_E2E_COOKIE_PORT", None)
            self.assertEqual(SERVER.listen_port(), 8765)

    def test_port_env_override(self) -> None:
        with mock.patch.dict(SERVER.os.environ, {"ROOKIE_E2E_COOKIE_PORT": "9123"}):
            self.assertEqual(SERVER.listen_port(), 9123)


class ClaimedE2eHelperTests(unittest.TestCase):
    def test_chrome_safe_storage_plants_chromium_account(self) -> None:
        with mock.patch.dict(CLAIMED.os.environ, {"ROOKIE_E2E_KEYCHAIN_ACCOUNT": "Chrome"}):
            accounts = CLAIMED.keychain_accounts("Chrome Safe Storage")
        self.assertIn("Chromium", accounts)
        self.assertIn("Chrome", accounts)

    def test_pick_cookie_port_honors_env(self) -> None:
        with mock.patch.dict(CLAIMED.os.environ, {"ROOKIE_E2E_COOKIE_PORT": "9333"}):
            self.assertEqual(CLAIMED.pick_cookie_port(), 9333)

    def test_cookies_db_has_name_reads_sqlite(self) -> None:
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "Default" / "Cookies"
            db.parent.mkdir(parents=True)
            connection = sqlite3.connect(db)
            connection.execute(
                "create table cookies (name text, host_key text, value text)"
            )
            connection.execute(
                "insert into cookies values ('rookie_ci', '127.0.0.1', 'bar')"
            )
            connection.commit()
            connection.close()
            self.assertTrue(CLAIMED.cookies_db_has_name(Path(tmp)))
            self.assertFalse(CLAIMED.cookies_db_has_name(Path(tmp), "missing"))
