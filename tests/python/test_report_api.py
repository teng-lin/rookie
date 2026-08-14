"""Wire-shape and request semantics of the generic report bindings.

These run against a synthetic home directory so a browser installed on the host
cannot decide whether an assertion passes.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import rookie_cookies

_PLAINTEXT_VALUES = {"Default": "default-value", "Profile 1": "profile-value"}

# A v10 Chromium blob no key can open, so the row is seen and then rejected.
_UNDECRYPTABLE = b"v10" + bytes(20)


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

    def test_chrome_profiles_prefers_last_used_without_changing_generic_order(
        self,
    ) -> None:
        with _synthetic_home() as home:
            root = _seed_chrome(home)
            (root / "Local State").write_text(
                json.dumps(
                    {
                        "profile": {
                            "last_used": "Profile 1",
                            "last_active_profiles": ["Profile 1", "Default"],
                            "info_cache": {
                                "Default": {"name": "Personal"},
                                "Profile 1": {"name": "Work"},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            generic = rookie_cookies.browser_profiles("chrome")
            preferred = rookie_cookies.chrome_profiles()
            report = rookie_cookies.chrome_profile("Work")

        self.assertEqual(generic[0]["profile"]["display_name"], "Personal")
        self.assertEqual(preferred[0]["profile"]["display_name"], "Work")
        self.assertEqual(len(report["profiles"]), 1)
        self.assertEqual(report["profiles"][0]["profile"]["display_name"], "Work")
        self.assertEqual(
            report["profiles"][0]["sources"][0]["cookies"][0]["value"],
            "profile-value",
        )

    def test_chrome_profile_keeps_invalid_activity_hint_as_a_typed_warning(
        self,
    ) -> None:
        with _synthetic_home() as home:
            root = _seed_chrome(home)
            (root / "Local State").write_text("{", encoding="utf-8")
            profiles = rookie_cookies.chrome_profiles()
            report = rookie_cookies.chrome_profile(
                profiles[0]["profile"]["profile_id"]
            )

        self.assertEqual(
            [profile["profile"]["display_name"] for profile in profiles],
            ["Default", "Profile 1"],
        )
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["profiles"]), 1)
        self.assertEqual(report["summary"]["browsers_detected"], 1)
        issues = {issue["code"]: issue for issue in report["issues"]}
        self.assertNotIn("browser_not_detected", issues)
        self.assertEqual(issues["local_state_invalid"]["severity"], "warning")
        self.assertEqual(issues["local_state_invalid"]["stage"], "discovery")


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
            self.assertEqual(
                sorted(source["source"]),
                ["format", "path", "path_lossy", "precedence", "role"],
            )
            self.assertEqual(source["source"]["role"], "persistent")
            self.assertEqual(source["source"]["format"], "chromium_sqlite")
            self.assertFalse(source["source"]["path_lossy"])
            self.assertIsInstance(source["source"]["precedence"], int)
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

    def test_rejected_rows_surface_as_error_issues_and_degrade_the_status(
        self,
    ) -> None:
        with _synthetic_home() as home:
            root = _seed_chrome(home, profiles=("Default",))
            _seed_chromium_profile(root, "Profile 1", _UNDECRYPTABLE)
            report = rookie_cookies.browser_report("chrome")

        # One profile still produced its cookie, so the request degrades to
        # partial rather than failing outright.
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["rows_seen"], 2)
        self.assertEqual(report["summary"]["cookies_emitted"], 1)
        self.assertEqual(report["summary"]["rows_skipped"], 1)

        by_name = {
            profile["profile"]["display_name"]: profile
            for profile in report["profiles"]
        }
        self.assertEqual(sorted(by_name), ["Default", "Profile 1"])

        healthy = by_name["Default"]["sources"][0]
        self.assertEqual(healthy["issues"], [])
        self.assertEqual(len(healthy["cookies"]), 1)
        self.assertEqual(healthy["stats"]["rows_skipped"], 0)

        rejected = by_name["Profile 1"]["sources"][0]
        self.assertEqual(rejected["cookies"], [])
        self.assertEqual(rejected["stats"]["rows_seen"], 1)
        self.assertEqual(rejected["stats"]["cookies_emitted"], 0)
        self.assertEqual(rejected["stats"]["rows_skipped"], 1)

        decrypt_failed = next(
            issue for issue in rejected["issues"] if issue["code"] == "decrypt_failed"
        )
        self.assertEqual(decrypt_failed["severity"], "error")
        self.assertEqual(decrypt_failed["stage"], "decrypt")
        self.assertEqual(decrypt_failed["occurrences"], 1)
        self.assertTrue(decrypt_failed["samples"])
        self.assertTrue(all(isinstance(s, str) for s in decrypt_failed["samples"]))
        self.assertIn("decrypt_failed", decrypt_failed["message"])

    def test_issue_samples_are_bounded_while_occurrences_counts_them_all(
        self,
    ) -> None:
        rejected_rows = rookie_cookies.MAX_ISSUE_SAMPLES + 4
        with _synthetic_home() as home:
            root = _seed_chrome(home, profiles=())
            _seed_chromium_profile(root, "Default", _UNDECRYPTABLE, rejected_rows)
            report = rookie_cookies.browser_report("chrome")

        source = report["profiles"][0]["sources"][0]
        self.assertEqual(source["stats"]["rows_skipped"], rejected_rows)

        issue = next(i for i in source["issues"] if i["code"] == "decrypt_failed")
        self.assertEqual(issue["occurrences"], rejected_rows)
        self.assertTrue(issue["samples"])
        # A corrupt database cannot dictate report size. The exported cap is the
        # ceiling, not the count: an engine may retain fewer, so truncation
        # shows up as fewer samples than occurrences rather than as a full list.
        self.assertLessEqual(
            len(issue["samples"]), rookie_cookies.MAX_ISSUE_SAMPLES
        )
        self.assertLess(len(issue["samples"]), issue["occurrences"])

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


class WireFormatTest(unittest.TestCase):
    """JSON is the intended consumption path, so every value must survive it."""

    def test_every_dto_round_trips_through_json_unchanged(self) -> None:
        with _synthetic_home() as home:
            root = _seed_chrome(home, profiles=("Default",))
            _seed_chromium_profile(root, "Profile 1", _UNDECRYPTABLE)
            browsers = rookie_cookies.supported_browsers()
            profiles = rookie_cookies.browser_profiles("chrome")
            # A report carrying cookies, counters, and issues covers every
            # value kind the conversion produces.
            report = rookie_cookies.browser_report("chrome")

        self.assertEqual(report["status"], "partial")
        self.assertTrue(any(source["issues"] for source in _sources(report)))
        self.assertTrue(any(source["cookies"] for source in _sources(report)))

        for value in (browsers, profiles, report):
            # A bytes or non-primitive leak raises here rather than comparing
            # unequal, so the encode and the decode are both assertions.
            self.assertEqual(json.loads(json.dumps(value)), value)


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


def _seed_chrome(home: Path, profiles=("Default", "Profile 1")) -> Path:
    """Install Chrome's stable root with one plaintext-cookie profile each."""
    root = _chrome_root(home)
    root.mkdir(parents=True, exist_ok=True)
    for profile in profiles:
        _seed_chromium_profile(root, profile, _PLAINTEXT_VALUES[profile])
    (root / "Local State").write_text("{}", encoding="utf-8")
    return root


def _seed_chromium_profile(root: Path, profile: str, value, rows: int = 1) -> None:
    """Write cookie rows, plaintext for `str` and encrypted for `bytes`."""
    plaintext, encrypted = (value, b"") if isinstance(value, str) else ("", value)
    database = root / profile / "Network" / "Cookies"
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(database))
    try:
        connection.execute(
            "CREATE TABLE meta (key TEXT NOT NULL UNIQUE PRIMARY KEY, value TEXT)"
        )
        connection.execute("INSERT INTO meta VALUES ('version', '23')")
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
        connection.executemany(
            "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, ?, ?, ?, 0, 0)",
            [
                ("session" if rows == 1 else "session-{}".format(row), plaintext, encrypted)
                for row in range(rows)
            ],
        )
        connection.commit()
    finally:
        connection.close()


def _sources(report):
    return [
        source for profile in report["profiles"] for source in profile["sources"]
    ]


def _is_opaque_id(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


if __name__ == "__main__":
    unittest.main()
