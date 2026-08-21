"""Unit tests for rookie_cookies's Python-level helpers."""

from __future__ import annotations

import http.cookiejar
import inspect
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
                "MAX_ISSUE_SAMPLES",
                "ChromiumPathOptions",
                "browser_profiles",
                "browser_report",
                "chrome_profile",
                "chrome_profiles",
                "chromium_based_detailed",
                "chromium_cookies_from_path",
                "chromium_cookies_from_path_detailed",
                "cookies_from_path",
                "create_cookie",
                "firefox_based_detailed",
                "firefox_profile",
                "firefox_profiles",
                "load_report",
                "supported_browsers",
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

    def test_canonical_direct_path_runtime_signatures(self) -> None:
        self.assertEqual(
            str(inspect.signature(rookie_cookies.cookies_from_path)),
            "(path, domains=None, timeout=None, cancellation=None)",
        )
        self.assertEqual(
            str(inspect.signature(rookie_cookies.chromium_cookies_from_path)),
            "(path, options=None)",
        )

        stub = Path(rookie_cookies.__file__).with_name("rookie_cookies.pyi").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "def cookies_from_path(\n"
            "    path: str,\n"
            "    domains: list[str] | None = None,\n"
            "    timeout: float | None = None,\n"
            "    cancellation: CancellationHandle | None = None,\n"
            ") -> CookieList:",
            stub,
        )
        self.assertIn(
            "path: str, options: ChromiumPathOptions | None = None",
            stub,
        )
        self.assertEqual(stub.count("class ChromiumPathOptions(TypedDict"), 1)
        self.assertEqual(
            str(
                inspect.signature(
                    rookie_cookies.chromium_cookies_from_path_detailed
                )
            ),
            "(path, options=None)",
        )

    def test_cookies_from_path_classifies_firefox_and_filters_domains(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "cookies.sqlite"
            _seed_firefox_database(
                db_path,
                [
                    (".example.test", "wanted", "value"),
                    ("other.test", "ignored", "value"),
                ],
            )
            cookies = rookie_cookies.cookies_from_path(
                str(db_path), ["example.test"]
            )

        self.assertEqual([cookie["name"] for cookie in cookies], ["wanted"])

    def test_cookies_from_path_rejects_once_its_timeout_budget_expires(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "cookies.sqlite"
            _seed_firefox_database(db_path, [(".example.test", "wanted", "value")])
            with self.assertRaisesRegex(RuntimeError, "operation timed out"):
                rookie_cookies.cookies_from_path(str(db_path), timeout=0.0)

    def test_cookies_from_path_rejects_an_already_cancelled_handle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "cookies.sqlite"
            _seed_firefox_database(db_path, [(".example.test", "wanted", "value")])
            handle = rookie_cookies.CancellationHandle()
            handle.cancel()
            with self.assertRaisesRegex(RuntimeError, "operation was cancelled"):
                rookie_cookies.cookies_from_path(str(db_path), cancellation=handle)

    def test_fault_classification_distinguishes_request_from_engine_errors(self) -> None:
        # RookieRequestError/RookieEngineError subclass ValueError/RuntimeError
        # respectively, so existing `except ValueError`/`except RuntimeError`
        # call sites keep working unchanged.
        self.assertTrue(issubclass(rookie_cookies.RookieRequestError, ValueError))
        self.assertTrue(issubclass(rookie_cookies.RookieEngineError, RuntimeError))
        self.assertTrue(issubclass(rookie_cookies.RookieStoppedError, RuntimeError))
        self.assertTrue(issubclass(rookie_cookies.RookieRequestError, rookie_cookies.RookieError))
        self.assertTrue(issubclass(rookie_cookies.RookieEngineError, rookie_cookies.RookieError))
        self.assertTrue(issubclass(rookie_cookies.RookieStoppedError, rookie_cookies.RookieError))

        missing = str(
            Path(tempfile.gettempdir()) / "no such parent directory" / "missing"
        )
        # An invalid explicit source is RookieSourceError/kind "source", not
        # plain RookieRequestError/kind "request" -- but RookieSourceError
        # subclasses RookieRequestError (and ValueError) precisely so this
        # `except RookieRequestError` written before that class existed keeps
        # catching it.
        with self.assertRaises(rookie_cookies.RookieRequestError):
            rookie_cookies.cookies_from_path(missing)

        try:
            rookie_cookies.cookies_from_path(missing)
        except rookie_cookies.RookieRequestError as error:
            self.assertIsInstance(error, rookie_cookies.RookieSourceError)
            self.assertEqual(error.kind, "source")
            self.assertEqual(error.code, "not_a_regular_file")
            self.assertIsNone(error.stop_reason)
            self.assertTrue(error.path_redacted)
            self.assertIsNone(error.source_kind)
            self.assertIsNone(error.target_os)
        else:  # pragma: no cover - guarded by the assertion above
            self.fail("missing direct path unexpectedly succeeded")

        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "cookies.sqlite"
            _seed_firefox_database(db_path, [(".example.test", "wanted", "value")])
            # A timeout is a cooperative stop, not a caller input mistake,
            # even though it is checked mid inspection of an explicit source
            # (which otherwise raises RookieRequestError). It gets its own
            # RookieStoppedError/RuntimeError class, distinct from
            # RookieEngineError -- see CHANGELOG.md.
            with self.assertRaises(rookie_cookies.RookieStoppedError) as raised:
                rookie_cookies.cookies_from_path(str(db_path), timeout=0.0)
            self.assertEqual(raised.exception.kind, "stopped")
            self.assertEqual(raised.exception.code, "timed_out")
            self.assertEqual(raised.exception.stop_reason, "timed_out")
            self.assertEqual(raised.exception.profile_ids, [])

    def test_python_option_shape_errors_are_request_errors(self) -> None:
        missing = str(Path(tempfile.gettempdir()) / "rookie-missing-db" / "Cookies")
        invalid_options = [
            "not-a-dict",
            {"unknown": True},
            {1: "value"},
            {"domains": "example.test"},
            {"domains": ["example.test", 1]},
            {"browser_id": 42},
            {"local_state_path": 42},
            {"plaintext_only": "yes"},
            {"timeout": "soon"},
            {"timeout": -1.0},
            {"timeout": float("inf")},
            {"cancellation": object()},
            {"browser_id": "chrome", "plaintext_only": True},
            {"local_state_path": "Local State", "plaintext_only": True},
            {"browser_id": "chrome", "local_state_path": "Local State"},
            {
                "browser_id": "chrome",
                "local_state_path": "Local State",
                "plaintext_only": True,
            },
        ]
        for options in invalid_options:
            with self.subTest(options=options):
                with self.assertRaises(rookie_cookies.RookieRequestError):
                    rookie_cookies.chromium_cookies_from_path(missing, options)

        with self.assertRaises(rookie_cookies.RookieRequestError):
            rookie_cookies.from_path(missing, timeout=-1.0)

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform in {"darwin", "win32"},
        "Chromium direct paths are supported on desktop targets",
    )
    def test_every_direct_path_and_legacy_chromium_function_uses_fault_classification(
        self,
    ) -> None:
        # Regression test: these previously bypassed classify_fault and fell
        # back to pyo3's blanket anyhow conversion, always raising a bare
        # RuntimeError instead of RookieEngineError/RookieRequestError.
        missing = str(Path(tempfile.gettempdir()) / "rookie-missing-db" / "Cookies")
        classified = (rookie_cookies.RookieRequestError, rookie_cookies.RookieEngineError)

        # firefox_profiles takes no arguments and can't be forced to fail
        # portably; assert it at least raises a classified type when the
        # host has no Firefox installation to enumerate, and tolerate an
        # empty successful result otherwise.
        try:
            rookie_cookies.firefox_profiles()
        except classified:
            pass
        except Exception as error:  # pragma: no cover - diagnostic on failure
            self.fail(f"firefox_profiles raised an unclassified exception: {error!r}")

        if sys.platform == "win32":
            with self.assertRaises(classified):
                rookie_cookies.chromium_based(missing, missing)
            with self.assertRaises(classified):
                rookie_cookies.chromium_based_detailed(missing, missing)
        else:
            with self.assertRaises(classified):
                rookie_cookies.chromium_based(missing, browser_id="chrome")
            with self.assertRaises(classified):
                rookie_cookies.chromium_based_detailed(missing, browser_id="chrome")

    def test_cancellation_handle_tracks_its_own_cancelled_state(self) -> None:
        handle = rookie_cookies.CancellationHandle()
        self.assertFalse(handle.is_cancelled())
        self.assertTrue(handle.cancel())
        self.assertTrue(handle.is_cancelled())
        self.assertFalse(handle.cancel())

    def test_timeout_rejects_values_a_duration_cannot_represent(self) -> None:
        with self.assertRaises(ValueError):
            rookie_cookies.cookies_from_path("/nonexistent", timeout=1e20)
        with self.assertRaises(ValueError):
            rookie_cookies.cookies_from_path("/nonexistent", timeout=-1.0)
        with self.assertRaises(ValueError):
            rookie_cookies.cookies_from_path("/nonexistent", timeout=float("nan"))

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform in {"darwin", "win32"},
        "Chromium direct paths are supported on desktop targets",
    )
    def test_canonical_chromium_plaintext_flat_detailed_and_domains(self) -> None:
        """Domains reduce the flat list; detailed output is unfiltered.

        0.6.0 removed the domain-filtered *detailed* path list: detailed
        output now comes from the snapshot job, which is never URL- or
        domain-reduced, because a reduced snapshot makes ``header()`` silently
        wrong. Asking for both is a request error rather than a silent
        widening, and the message names the two things a caller can do
        instead.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "Cookies"
            _seed_chromium_database(
                db_path,
                [
                    (".example.test", "wanted", "plain", b""),
                    ("other.test", "ignored", "plain", b""),
                ],
            )
            cookies = rookie_cookies.chromium_cookies_from_path(
                str(db_path), {"domains": ["example.test"], "plaintext_only": True}
            )
            detailed = rookie_cookies.chromium_cookies_from_path_detailed(
                str(db_path), {"plaintext_only": True}
            )
            with self.assertRaises(rookie_cookies.RookieRequestError) as combined:
                rookie_cookies.chromium_cookies_from_path_detailed(
                    str(db_path),
                    {"domains": ["example.test"], "plaintext_only": True},
                )

        self.assertEqual([cookie["name"] for cookie in cookies], ["wanted"])
        self.assertIn("domains", str(combined.exception))
        # The detailed list keeps every row, and its projection of the one the
        # flat list kept is identical.
        self.assertEqual(
            sorted(record["cookie"]["name"] for record in detailed),
            ["ignored", "wanted"],
        )
        wanted = next(
            record for record in detailed if record["cookie"]["name"] == "wanted"
        )
        self.assertEqual(wanted["cookie"], cookies[0])

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform in {"darwin", "win32"},
        "Chromium direct paths are supported on desktop targets",
    )
    def test_plaintext_only_is_a_whole_request_guarantee(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "Cookies"
            _seed_chromium_database(
                db_path,
                [
                    (".example.test", "wanted", "plain", b""),
                    ("other.test", "encrypted", "", b"v10encrypted"),
                ],
            )
            with self.assertRaisesRegex(RuntimeError, "no browser key identity"):
                rookie_cookies.chromium_cookies_from_path(
                    str(db_path),
                    {"domains": ["example.test"], "plaintext_only": True},
                )

    def test_chromium_options_reject_shape_errors_before_database_io(self) -> None:
        missing = str(Path(tempfile.gettempdir()) / "rookie-python-missing-Cookies")
        invalid_options = [
            [],
            {"unknown": True},
            {1: "value"},
            {"domains": "example.test"},
            {"domains": ["example.test", 1]},
            {"browser_id": 1},
            {"local_state_path": 1},
            {"plaintext_only": 1},
            {"browser_id": "chrome", "plaintext_only": True},
            {"local_state_path": "Local State", "plaintext_only": True},
        ]
        for options in invalid_options:
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    rookie_cookies.chromium_cookies_from_path(missing, options)

    @unittest.skipUnless(
        sys.platform.startswith("linux") or sys.platform in {"darwin", "win32"},
        "Chromium direct paths are supported on desktop targets",
    )
    def test_none_false_and_empty_credential_selectors_follow_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "Cookies"
            _seed_chromium_database(
                db_path, [(".example.test", "wanted", "plain", b"")]
            )
            # Every desktop target agrees here as of 0.6.0. Windows used to
            # reject a credential-less Chromium path with
            # MissingLocalStateFile *before* attempting extraction, so a fully
            # plaintext database failed there while succeeding on Unix. Only a
            # genuinely encrypted row demands credentials now, so this branch
            # is deliberately no longer platform-split.
            for options in (None, {}, {"plaintext_only": False}):
                with self.subTest(options=options):
                    cookies = rookie_cookies.chromium_cookies_from_path(
                        str(db_path), options
                    )
                    self.assertEqual(cookies[0]["name"], "wanted")

            plaintext = rookie_cookies.chromium_cookies_from_path(
                str(db_path), {"plaintext_only": True}
            )
            self.assertEqual(plaintext[0]["name"], "wanted")

            # An empty selector is a request fault (rookie_cookies.RookieRequestError,
            # a ValueError subclass), not an engine fault: the caller can fix it by
            # passing a non-empty value.
            with self.assertRaises(ValueError):
                rookie_cookies.chromium_cookies_from_path(
                    str(db_path), {"browser_id": ""}
                )
            with self.assertRaises(ValueError):
                rookie_cookies.chromium_cookies_from_path(
                    str(db_path), {"local_state_path": ""}
                )

    def test_platform_browser_exports_match_support_matrix(self) -> None:
        platform_exports = {"cachy", "internet_explorer", "octo_browser", "opera_gx", "safari"}
        if sys.platform.startswith("linux"):
            expected = {"cachy"}
        elif sys.platform == "darwin":
            expected = {"opera_gx", "safari"}
        elif sys.platform == "win32":
            expected = {"internet_explorer", "octo_browser", "opera_gx"}
        else:
            expected = set()

        self.assertEqual(platform_exports.intersection(rookie_cookies.__all__), expected)
        for name in platform_exports:
            self.assertEqual(hasattr(rookie_cookies, name), name in expected, name)

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
        self.assertFalse(cookie.discard)
        self.assertTrue(cookie.has_nonstandard_attr("HTTPOnly"))

    def test_session_cookie_is_discarded(self) -> None:
        cookie_data = dict(COOKIE)
        cookie_data["expires"] = None

        cookie = rookie_cookies.create_cookie(
            host=cookie_data["domain"],
            path=cookie_data["path"],
            secure=cookie_data["secure"],
            expires=cookie_data["expires"],
            name=cookie_data["name"],
            value=cookie_data["value"],
            http_only=cookie_data["http_only"],
        )

        self.assertIsNone(cookie.expires)
        self.assertTrue(cookie.discard)

    def test_firefox_context_distinguishes_container_collisions(self) -> None:
        # ignore_cleanup_errors: Windows can keep cookies.sqlite mapped after
        # rusqlite returns (WinError 32). Python 3.14 no longer swallows that
        # on TemporaryDirectory exit.
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
            db_path = Path(temp_dir) / "cookies.sqlite"
            connection = sqlite3.connect(db_path)
            try:
                connection.executescript(
                    """
                    CREATE TABLE moz_cookies (
                        host TEXT, path TEXT, isSecure INTEGER, expiry INTEGER,
                        name TEXT, value TEXT, isHttpOnly INTEGER,
                        sameSite INTEGER, originAttributes TEXT
                    );
                    INSERT INTO moz_cookies VALUES
                        ('.example.test', '/', 1, 0, 'session', 'work', 1, 1,
                         '^userContextId=2&partitionKey=%28https%2Cwork.example%29'),
                        ('.example.test', '/', 1, 0, 'session', 'personal', 1, 1,
                         '^userContextId=1&partitionKey=%28https%2Cpersonal.example%29');
                    """
                )
                connection.commit()
            finally:
                connection.close()

            records = rookie_cookies.firefox_based_detailed(str(db_path))

        self.assertEqual(len(records), 2)
        self.assertTrue(all(sorted(record) == ["context", "cookie"] for record in records))
        contexts = {
            record["cookie"]["value"]: record["context"] for record in records
        }
        self.assertEqual(contexts["work"]["user_context_id"], 2)
        self.assertEqual(contexts["work"]["partition_key"], "(https,work.example)")
        self.assertIsNone(contexts["work"]["top_frame_site_key"])
        self.assertEqual(contexts["personal"]["user_context_id"], 1)
        self.assertIsNone(contexts["personal"]["top_frame_site_key"])
        self.assertEqual(
            contexts["personal"]["origin_attributes"],
            "^userContextId=1&partitionKey=%28https%2Cpersonal.example%29",
        )

    @unittest.skipIf(sys.platform == "win32", "Windows uses an explicit Local State path")
    def test_encrypted_chromium_path_without_identity_is_explicit_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "Cookies"
            with sqlite3.connect(db_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE meta (
                        key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
                        value LONGVARCHAR
                    );
                    INSERT INTO meta (key, value) VALUES ('version', '23');
                    CREATE TABLE cookies (
                        host_key TEXT, path TEXT, is_secure INTEGER,
                        expires_utc INTEGER, name TEXT, value TEXT,
                        encrypted_value BLOB, is_httponly INTEGER,
                        samesite INTEGER
                    );
                    INSERT INTO cookies VALUES (
                        '.example.com', '/', 1, 0, 'session', '',
                        X'763131656E63727970746564', 1, 0
                    );
                    """
                )

            with self.assertRaisesRegex(
                RuntimeError, r"no browser key identity.*browser_id"
            ):
                rookie_cookies.chromium_based(str(db_path))

    @unittest.skipIf(sys.platform == "win32", "Windows uses an explicit Local State path")
    def test_chromium_browser_ids_are_registry_identities_not_profile_selectors(
        self,
    ) -> None:
        missing_db = str(Path(tempfile.gettempdir()) / "rookie-python-missing-Cookies")
        profile_like_id = "0" * 64
        invalid_identities = [
            ("definitely-not-a-browser", r'unknown browser id "definitely-not-a-browser"'),
            (
                "firefox",
                r'browser id "firefox" resolves to the gecko engine, not Chromium',
            ),
            (profile_like_id, rf'unknown browser id "{profile_like_id}"'),
        ]

        for browser_id, message in invalid_identities:
            for extract in (
                rookie_cookies.chromium_based,
                rookie_cookies.chromium_based_detailed,
            ):
                with self.subTest(browser_id=browser_id, extract=extract.__name__):
                    with self.assertRaisesRegex(RuntimeError, message):
                        extract(missing_db, browser_id=browser_id)

    def test_clear_session_cookies_preserves_persistent_cookies(self) -> None:
        session_cookie = dict(COOKIE)
        session_cookie.update(name="session", expires=None)
        persistent_cookie = dict(COOKIE)
        persistent_cookie.update(name="persistent", expires=4_102_444_800)
        jar = rookie_cookies.to_cookiejar([session_cookie, persistent_cookie])

        jar.clear_session_cookies()

        self.assertEqual([cookie.name for cookie in jar], ["persistent"])

    def test_session_cookies_are_not_persisted_by_default(self) -> None:
        session_cookie = dict(COOKIE)
        session_cookie.update(name="session", expires=None)
        persistent_cookie = dict(COOKIE)
        persistent_cookie.update(name="persistent", expires=4_102_444_800)

        with tempfile.TemporaryDirectory(prefix="rookie-python-cookiejar-") as temp:
            path = Path(temp) / "cookies.txt"
            jar = http.cookiejar.MozillaCookieJar(str(path))
            for cookie in rookie_cookies.to_cookiejar(
                [session_cookie, persistent_cookie]
            ):
                jar.set_cookie(cookie)
            jar.save(ignore_discard=False, ignore_expires=False)

            reloaded = http.cookiejar.MozillaCookieJar(str(path))
            reloaded.load(ignore_discard=False, ignore_expires=False)

        self.assertEqual([cookie.name for cookie in reloaded], ["persistent"])

    def test_to_cookiejar_returns_usable_cookiejar(self) -> None:
        jar = rookie_cookies.to_cookiejar([COOKIE])

        self.assertIsInstance(jar, http.cookiejar.CookieJar)
        self.assertEqual(len(jar), 1)
        cookie = next(iter(jar))
        self.assertEqual(cookie.name, "session")
        self.assertEqual(cookie.value, "abc123")

    def test_to_netscape_serializes_cookie(self) -> None:
        output = rookie_cookies.to_netscape([COOKIE])

        self.assertEqual(
            output,
            f"# Netscape HTTP Cookie File\n"
            f"# Generated by rookie-cookies {rookie_cookies.version()}\n"
            f"# Edit at your own risk.\n\n"
            f"#HttpOnly_.example.test\tTRUE\t/\tTRUE\t1700000000\t"
            f"session\tabc123\n",
        )

    def test_to_netscape_escapes_malicious_fields_byte_exactly(self) -> None:
        cookie = {
            **COOKIE,
            "domain": "#HttpOnly_.exa\tmple\r.test",
            "path": "/line\npath",
            "expires": None,
            "name": "na\tme",
            "value": "safe\n.evil.test\tTRUE\t/\tTRUE\t1\tforged\tvalue\r",
            "secure": False,
        }

        output = rookie_cookies.to_netscape([cookie])

        self.assertEqual(
            output.encode("utf-8"),
            (
                f"# Netscape HTTP Cookie File\n"
                f"# Generated by rookie-cookies {rookie_cookies.version()}\n"
                f"# Edit at your own risk.\n\n"
                f"#HttpOnly_%23HttpOnly_.exa%09mple%0D.test\tFALSE\t/line%0Apath\tFALSE\t"
                f"0\tna%09me\tsafe%0A.evil.test%09TRUE%09/%09TRUE%091%09"
                f"forged%09value%0D\n"
            ).encode("utf-8"),
        )
        self.assertEqual(len(output.splitlines()), 5)

    def test_to_netscape_escapes_invalid_runtime_expiry_text(self) -> None:
        cookie = {**COOKIE, "expires": "1\r\nforged"}

        output = rookie_cookies.to_netscape([cookie])

        self.assertIn("\t1%0D%0Aforged\t", output)
        self.assertEqual(len(output.splitlines()), 5)

    def test_to_netscape_preserves_hashes_outside_domain(self) -> None:
        cookie = {
            **COOKIE,
            "path": "/fragment#anchor",
            "name": "name#suffix",
            "value": "value#fragment",
        }

        record = rookie_cookies.to_netscape([cookie]).splitlines()[-1]

        self.assertEqual(
            record,
            "#HttpOnly_.example.test\tTRUE\t/fragment#anchor\tTRUE\t1700000000\t"
            "name#suffix\tvalue#fragment",
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
        connection.execute("PRAGMA user_version = 16")
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
            ) VALUES (?, '/', 0, 1700000000000, ?, ?, 0, 0)
            """,
            rows,
        )
        connection.commit()
    finally:
        connection.close()


def _seed_chromium_database(path: Path, rows) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(
            """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO meta VALUES ('version', '23');
            CREATE TABLE cookies (
              host_key TEXT NOT NULL, path TEXT NOT NULL,
              is_secure INTEGER NOT NULL, expires_utc INTEGER NOT NULL,
              name TEXT NOT NULL, value TEXT NOT NULL,
              encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL
            );
            """
        )
        connection.executemany(
            "INSERT INTO cookies VALUES (?, '/', 0, 0, ?, ?, ?, 0, 0)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    unittest.main()
