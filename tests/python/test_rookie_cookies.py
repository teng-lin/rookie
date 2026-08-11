"""Unit tests for rookie_cookies's Python-level helpers."""

from __future__ import annotations

import http.cookiejar
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rookie_cookies

COOKIE = {
    "domain": ".example.test",
    "path": "/",
    "secure": True,
    "expires": 1_700_000_000,
    "name": "session",
    "value": "abc123",
    "http_only": True,
}


class RookieCookiesHelpersTest(unittest.TestCase):
    def test_version_is_nonempty_semver_string(self) -> None:
        self.assertRegex(rookie_cookies.version(), r"^\d+\.\d+\.\d+")

    def test_all_exports_are_defined(self) -> None:
        self.assertTrue(
            {
                "create_cookie",
                "firefox_profile",
                "firefox_profiles",
                "to_cookiejar",
                "to_netscape",
                "zen",
            }.issubset(
                rookie_cookies.__all__
            )
        )
        self.assertNotIn("to_dict", rookie_cookies.__all__)
        for name in rookie_cookies.__all__:
            self.assertTrue(hasattr(rookie_cookies, name), name)

    def test_create_cookie_maps_cookie_fields(self) -> None:
        cookie = rookie_cookies.create_cookie(
            host=COOKIE["domain"],
            path=COOKIE["path"],
            secure=COOKIE["secure"],
            expires=COOKIE["expires"],
            name=COOKIE["name"],
            value=COOKIE["value"],
            http_only=COOKIE["http_only"],
        )

        self.assertIsInstance(cookie, http.cookiejar.Cookie)
        self.assertEqual(cookie.domain, ".example.test")
        self.assertTrue(cookie.domain_initial_dot)
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc123")
        self.assertTrue(cookie.secure)
        self.assertEqual(cookie.expires, 1_700_000_000)
        self.assertTrue(cookie.has_nonstandard_attr("HTTPOnly"))

    def test_to_cookiejar_returns_usable_cookiejar(self) -> None:
        jar = rookie_cookies.to_cookiejar([COOKIE])

        self.assertIsInstance(jar, http.cookiejar.CookieJar)
        self.assertEqual(len(jar), 1)
        cookie = next(iter(jar))
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc123")

    def test_to_netscape_serializes_cookie(self) -> None:
        output = rookie_cookies.to_netscape([COOKIE])

        self.assertIn("# Netscape HTTP Cookie File", output)
        self.assertIn(
            "#HttpOnly_.example.test\tTRUE\t/\tTRUE\t1700000000\tsession\tabc123",
            output,
        )

    def test_to_netscape_handles_empty_cookie_list(self) -> None:
        output = rookie_cookies.to_netscape([])

        self.assertRegex(output, r"^# Netscape HTTP Cookie File\n")

    def test_firefox_profiles_list_and_extract_secondary_profile(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rookie-python-firefox-") as temp:
            root, environment = _firefox_root(Path(temp))
            default = root / "Profiles" / "default-release"
            work = root / "Profiles" / "work"
            default.mkdir(parents=True)
            work.mkdir(parents=True)
            (root / "profiles.ini").write_text(
                """\
[InstallTest]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/work
""",
                encoding="utf-8",
            )
            _seed_firefox_database(default / "cookies.sqlite", [])
            _seed_firefox_database(
                work / "cookies.sqlite",
                [(".example.test", "selected", "secondary")],
            )

            with mock.patch.dict(os.environ, environment, clear=False):
                profiles = rookie_cookies.firefox_profiles()
                cookies = rookie_cookies.firefox_profile(
                    "work", ["example.test"]
                )

        self.assertEqual(
            [(profile["name"], profile["is_default"]) for profile in profiles],
            [("default-release", True), ("work", False)],
        )
        self.assertTrue(all(isinstance(profile["path"], str) for profile in profiles))
        self.assertEqual(len(cookies), 1)
        self.assertEqual(
            cookies[0],
            {
                "domain": ".example.test",
                "path": "/",
                "secure": False,
                "expires": 1_700_000_000,
                "name": "selected",
                "value": "secondary",
                "http_only": False,
                "same_site": 0,
            },
        )


def _firefox_root(temp: Path):
    if sys.platform == "win32":
        roaming = temp / "Roaming"
        local = temp / "Local"
        return roaming / "Mozilla" / "Firefox", {
            "APPDATA": str(roaming),
            "LOCALAPPDATA": str(local),
        }
    if sys.platform == "darwin":
        return temp / "Library" / "Application Support" / "Firefox", {
            "HOME": str(temp)
        }
    return temp / ".mozilla" / "firefox", {"HOME": str(temp)}


def _seed_firefox_database(path: Path, rows) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            """
            CREATE TABLE moz_cookies (
              host TEXT NOT NULL,
              path TEXT NOT NULL,
              isSecure INTEGER NOT NULL,
              expiry INTEGER NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              isHttpOnly INTEGER NOT NULL,
              sameSite INTEGER NOT NULL
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO moz_cookies (
              host, path, isSecure, expiry, name, value, isHttpOnly, sameSite
            ) VALUES (?, '/', 0, 1700000000, ?, ?, 0, 0)
            """,
            rows,
        )
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
