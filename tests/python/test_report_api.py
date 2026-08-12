"""Wire-shape and request semantics of the generic report bindings.

These run against a synthetic home directory so a browser installed on the host
cannot decide whether an assertion passes.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rookie_cookies


class SupportedBrowsersTest(unittest.TestCase):
    def test_descriptors_expose_the_registry_without_touching_the_disk(self) -> None:
        with _synthetic_home():
            browsers = rookie_cookies.supported_browsers()

        self.assertTrue(browsers)
        by_id = {browser["id"]: browser for browser in browsers}
        self.assertIn("chrome", by_id)

        chrome = by_id["chrome"]
        self.assertEqual(
            sorted(chrome),
            ["aliases", "capabilities", "display_name", "engine", "id"],
        )
        self.assertEqual(chrome["engine"], "chromium")
        self.assertIsInstance(chrome["display_name"], str)
        self.assertTrue(all(isinstance(alias, str) for alias in chrome["aliases"]))
        self.assertEqual(
            sorted(chrome["capabilities"]),
            [
                "available_decryption_tiers",
                "declared_decryption_tiers",
                "persistent_formats",
                "session_formats",
            ],
        )
        self.assertIn("chromium_sqlite", chrome["capabilities"]["persistent_formats"])
        for tiers in chrome["capabilities"].values():
            self.assertTrue(all(isinstance(tier, str) for tier in tiers))


class BrowserProfilesTest(unittest.TestCase):
    def test_unknown_browser_id_raises(self) -> None:
        with _synthetic_home():
            with self.assertRaises(RuntimeError) as raised:
                rookie_cookies.browser_profiles("not-a-browser")

        self.assertIn("unknown browser id", str(raised.exception))

    def test_absent_browser_returns_an_empty_list(self) -> None:
        with _synthetic_home():
            self.assertEqual(rookie_cookies.browser_profiles("chrome"), [])

    def test_descriptors_carry_identity_and_sources(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            profiles = rookie_cookies.browser_profiles("chrome")

        self.assertEqual(len(profiles), 2)
        for profile in profiles:
            self.assertEqual(sorted(profile), ["is_default", "profile", "sources"])
            self.assertIsInstance(profile["is_default"], bool)
            identity = profile["profile"]
            self.assertEqual(
                sorted(identity),
                [
                    "browser_id",
                    "display_name",
                    "installation_id",
                    "path",
                    "path_lossy",
                    "profile_id",
                ],
            )
            self.assertEqual(identity["browser_id"], "chrome")
            self.assertTrue(_is_opaque_id(identity["profile_id"]))
            self.assertTrue(_is_opaque_id(identity["installation_id"]))
            self.assertFalse(identity["path_lossy"])

            self.assertEqual(len(profile["sources"]), 1)
            source = profile["sources"][0]
            self.assertEqual(
                sorted(source),
                ["format", "path", "path_lossy", "precedence", "role"],
            )
            self.assertEqual(source["role"], "persistent")
            self.assertEqual(source["format"], "chromium_sqlite")
            self.assertIsInstance(source["precedence"], int)

        self.assertEqual(
            sorted(profile["is_default"] for profile in profiles), [False, True]
        )


class BrowserReportTest(unittest.TestCase):
    def test_unknown_browser_id_raises(self) -> None:
        with _synthetic_home():
            with self.assertRaises(RuntimeError) as raised:
                rookie_cookies.browser_report("not-a-browser")

        self.assertIn("unknown browser id", str(raised.exception))

    def test_unknown_profile_id_raises(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            with self.assertRaises(RuntimeError) as raised:
                rookie_cookies.browser_report("chrome", "0" * 64)

        self.assertIn("unknown chrome profile id", str(raised.exception))

    def test_absent_browser_reports_no_sources_instead_of_raising(self) -> None:
        with _synthetic_home():
            report = rookie_cookies.browser_report("chrome")

        self.assertEqual(report["status"], "no_sources")
        self.assertEqual(report["profiles"], [])
        self.assertEqual(report["summary"]["registered_browsers"], 1)
        self.assertEqual(report["summary"]["browsers_detected"], 0)
        self.assertEqual(report["summary"]["browsers_not_detected"], 1)
        self.assertEqual(report["summary"]["profiles_discovered"], 0)

        self.assertEqual(len(report["issues"]), 1)
        issue = report["issues"][0]
        self.assertEqual(
            sorted(issue),
            [
                "browser_id",
                "code",
                "installation_id",
                "message",
                "occurrences",
                "profile_id",
                "samples",
                "severity",
                "stage",
            ],
        )
        self.assertEqual(issue["code"], "browser_not_detected")
        self.assertEqual(issue["severity"], "info")
        self.assertEqual(issue["stage"], "discovery")
        self.assertEqual(issue["browser_id"], "chrome")
        self.assertIsNone(issue["installation_id"])
        self.assertIsNone(issue["profile_id"])
        self.assertEqual(issue["samples"], [])
        self.assertIsInstance(issue["message"], str)

    def test_wire_shape_keeps_cookies_on_the_source_they_came_from(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            report = rookie_cookies.browser_report("chrome")

        self.assertEqual(sorted(report), ["issues", "profiles", "status", "summary"])
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["issues"], [])
        self.assertEqual(
            sorted(report["summary"]),
            [
                "browsers_detected",
                "browsers_not_detected",
                "cookies_emitted",
                "counters_saturated",
                "installations_discovered",
                "profiles_discovered",
                "registered_browsers",
                "rows_seen",
                "rows_skipped",
                "sources_failed",
                "sources_succeeded",
            ],
        )
        self.assertEqual(report["summary"]["profiles_discovered"], 2)
        self.assertEqual(report["summary"]["sources_succeeded"], 2)
        self.assertEqual(report["summary"]["sources_failed"], 0)
        self.assertEqual(report["summary"]["cookies_emitted"], 2)
        self.assertFalse(report["summary"]["counters_saturated"])

        self.assertEqual(len(report["profiles"]), 2)
        values = []
        for profile in report["profiles"]:
            self.assertEqual(
                sorted(profile), ["issues", "profile", "sources", "stats"]
            )
            self.assertEqual(profile["profile"]["browser_id"], "chrome")
            self.assertTrue(_is_opaque_id(profile["profile"]["profile_id"]))
            self.assertEqual(len(profile["sources"]), 1)

            source = profile["sources"][0]
            self.assertEqual(
                sorted(source),
                [
                    "acquisition_strategy",
                    "cookies",
                    "issues",
                    "selected",
                    "source",
                    "stats",
                    "status",
                ],
            )
            self.assertEqual(source["status"], "succeeded")
            self.assertTrue(source["selected"])
            self.assertIsInstance(source["acquisition_strategy"], str)
            self.assertEqual(source["source"]["role"], "persistent")
            self.assertEqual(source["source"]["format"], "chromium_sqlite")
            self.assertEqual(
                sorted(source["stats"]),
                [
                    "acquisition_attempts",
                    "cookies_emitted",
                    "counters_saturated",
                    "rows_seen",
                    "rows_skipped",
                ],
            )
            self.assertEqual(source["stats"]["cookies_emitted"], 1)
            self.assertEqual(source["stats"]["rows_skipped"], 0)

            self.assertEqual(len(source["cookies"]), 1)
            cookie = source["cookies"][0]
            # Report cookies keep the exact legacy selector shape.
            self.assertEqual(
                cookie,
                {
                    "domain": ".example.test",
                    "path": "/",
                    "secure": False,
                    "expires": None,
                    "name": "session",
                    "value": cookie["value"],
                    "http_only": False,
                    "same_site": 0,
                },
            )
            values.append(cookie["value"])

        # The same cookie name in two profiles stays separated by profile group.
        self.assertEqual(sorted(values), ["default-value", "profile-value"])
        self.assertEqual(
            len({profile["profile"]["profile_id"] for profile in report["profiles"]}),
            2,
        )

    def test_selection_uses_the_profile_id_from_browser_profiles(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            profiles = rookie_cookies.browser_profiles("chrome")
            default = next(
                profile for profile in profiles if profile["is_default"]
            )
            selected = default["profile"]["profile_id"]
            report = rookie_cookies.browser_report("chrome", selected)

        self.assertEqual(len(report["profiles"]), 1)
        self.assertEqual(report["profiles"][0]["profile"]["profile_id"], selected)

    def test_domain_filter_reaches_the_report(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            matched = rookie_cookies.browser_report("chrome", None, ["example.test"])
            unmatched = rookie_cookies.browser_report("chrome", None, ["absent.test"])

        self.assertEqual(matched["summary"]["cookies_emitted"], 2)
        self.assertEqual(unmatched["summary"]["cookies_emitted"], 0)
        self.assertEqual(unmatched["summary"]["sources_succeeded"], 2)
        self.assertEqual(unmatched["status"], "complete")


class LoadReportTest(unittest.TestCase):
    def test_uninstalled_browsers_are_counted_rather_than_reported(self) -> None:
        with _synthetic_home():
            registered = rookie_cookies.supported_browsers()
            report = rookie_cookies.load_report()

        self.assertEqual(report["status"], "no_sources")
        self.assertEqual(report["profiles"], [])
        self.assertEqual(report["issues"], [])
        self.assertEqual(report["summary"]["registered_browsers"], len(registered))
        self.assertEqual(
            report["summary"]["browsers_not_detected"],
            report["summary"]["registered_browsers"],
        )
        self.assertEqual(report["summary"]["browsers_detected"], 0)

    def test_installed_browser_reaches_the_combined_report(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            report = rookie_cookies.load_report(["example.test"])

        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["summary"]["browsers_detected"], 1)
        self.assertEqual(report["summary"]["cookies_emitted"], 2)
        self.assertEqual(
            {profile["profile"]["browser_id"] for profile in report["profiles"]},
            {"chrome"},
        )


@contextlib.contextmanager
def _synthetic_home():
    """Point every root-discovery variable at one empty temporary directory."""
    with tempfile.TemporaryDirectory(prefix="rookie-python-report-") as temp:
        home = Path(temp)
        environment = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "LOCALAPPDATA": str(home / "AppData" / "Local"),
            "APPDATA": str(home / "AppData" / "Roaming"),
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            os.environ.pop("CHROME_CONFIG_HOME", None)
            yield home


def _chrome_root(home: Path) -> Path:
    if sys.platform == "win32":
        return home / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Google" / "Chrome"
    return home / ".config" / "google-chrome"


def _seed_chrome(home: Path) -> Path:
    """Install Chrome's stable root with two plaintext-cookie profiles."""
    root = _chrome_root(home)
    _seed_chromium_profile(root, "Default", "default-value")
    _seed_chromium_profile(root, "Profile 1", "profile-value")
    (root / "Local State").write_text("{}", encoding="utf-8")
    return root


def _seed_chromium_profile(root: Path, profile: str, value: str) -> None:
    database = root / profile / "Network" / "Cookies"
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database))
    try:
        connection.execute(
            """
            CREATE TABLE cookies (
              host_key TEXT NOT NULL,
              path TEXT NOT NULL,
              is_secure INTEGER NOT NULL,
              expires_utc INTEGER NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              encrypted_value BLOB NOT NULL,
              is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'session', ?, ?, 0, 0)",
            (value, b""),
        )
        connection.commit()
    finally:
        connection.close()


def _is_opaque_id(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


if __name__ == "__main__":
    unittest.main()
