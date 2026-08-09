"""Unit tests for rookiepy's Python-level helpers."""

from __future__ import annotations

import http.cookiejar
import unittest

import rookiepy


COOKIE = {
    "domain": ".example.test",
    "path": "/",
    "secure": True,
    "expires": 1_700_000_000,
    "name": "session",
    "value": "abc123",
    "http_only": True,
}


class RookiepyHelpersTest(unittest.TestCase):
    def test_version_is_nonempty_semver_string(self) -> None:
        self.assertRegex(rookiepy.version(), r"^\d+\.\d+\.\d+")

    def test_all_exports_are_defined(self) -> None:
        self.assertTrue(
            {"create_cookie", "to_cookiejar", "to_netscape"}.issubset(rookiepy.__all__)
        )
        self.assertNotIn("to_dict", rookiepy.__all__)
        for name in rookiepy.__all__:
            self.assertTrue(hasattr(rookiepy, name), name)

    def test_create_cookie_maps_cookie_fields(self) -> None:
        cookie = rookiepy.create_cookie(
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
        jar = rookiepy.to_cookiejar([COOKIE])

        self.assertIsInstance(jar, http.cookiejar.CookieJar)
        self.assertEqual(len(jar), 1)
        cookie = next(iter(jar))
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc123")

    def test_to_netscape_serializes_cookie(self) -> None:
        output = rookiepy.to_netscape([COOKIE])

        self.assertIn("# Netscape HTTP Cookie File", output)
        self.assertIn("#HttpOnly_.example.test\tTRUE\t/\tTRUE\t1700000000\tsession\tabc123", output)

    def test_to_netscape_handles_empty_cookie_list(self) -> None:
        output = rookiepy.to_netscape([])

        self.assertRegex(output, r"^# Netscape HTTP Cookie File\n")


if __name__ == "__main__":
    unittest.main()
