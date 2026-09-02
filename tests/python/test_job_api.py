"""Job-layer `read` / `jar` / `from_path` / `profiles` / `report` bindings."""

from __future__ import annotations

import http.cookiejar
import sqlite3
import tempfile
import unittest
from pathlib import Path

import rookie_cookies

from test_report_api import (
    _UNDECRYPTABLE,
    _chrome_root,
    _seed_chrome,
    _seed_chromium_profile,
    _synthetic_home,
)

_COOKIE_KEYS = {
    "domain",
    "path",
    "secure",
    "http_only",
    "same_site",
    "expires",
    "name",
    "value",
}


def _seed_partitioned_gecko(path: Path) -> Path:
    """A Gecko store holding one partitioned row beside one unpartitioned one.

    Small and local on purpose: the exhaustive engine-identity matrix lives in
    `test_isolation_corpus.py`. All this needs is a snapshot that *is*
    isolated, so the fail-closed jar and the send-context demand have
    something real to refuse.
    """
    connection = sqlite3.connect(str(path))
    try:
        connection.execute("PRAGMA user_version = 16")
        connection.execute(
            """
            CREATE TABLE moz_cookies (
              host TEXT NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              path TEXT NOT NULL,
              isSecure INTEGER NOT NULL,
              isHttpOnly INTEGER NOT NULL,
              sameSite INTEGER NOT NULL,
              expiry INTEGER NOT NULL,
              originAttributes TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO moz_cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "embedded.example.test",
                    "plain",
                    "unpartitioned",
                    "/",
                    1,
                    0,
                    0,
                    4102444800000,
                    "",
                ),
                (
                    "embedded.example.test",
                    "chips",
                    "partitioned",
                    "/",
                    1,
                    0,
                    0,
                    4102444800000,
                    "^partitionKey=%28https%2Ctop.example.test%29",
                ),
            ],
        )
        connection.commit()
    finally:
        connection.close()
    return path


class JobApiTest(unittest.TestCase):
    def test_read_requires_browser(self) -> None:
        with self.assertRaises(TypeError):
            rookie_cookies.read()  # type: ignore[call-arg]

    def test_no_top_level_header(self) -> None:
        self.assertFalse(hasattr(rookie_cookies, "header"))
        self.assertNotIn("header", rookie_cookies.__all__)

    def test_as_list_schema_and_iter(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            result = rookie_cookies.read(browser="chrome", include_expired=True)
        rows = result.as_list()
        self.assertGreater(len(result), 0)
        self.assertTrue(result)
        for row, iterated in zip(rows, result):
            self.assertEqual(set(row), _COOKIE_KEYS)
            self.assertEqual(row, iterated)
            self.assertIsInstance(row["same_site"], int)

    def test_no_profile_read_set_equals_chrome(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            via_chrome = rookie_cookies.chrome()
            via_read = rookie_cookies.read(browser="chrome", include_expired=True).as_list()

        def key(row: dict) -> tuple:
            return (row["domain"], row["path"], row["name"], row["value"])

        self.assertEqual(sorted(via_chrome, key=key), sorted(via_read, key=key))

    def test_jar_is_not_url_filtered(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            jar = rookie_cookies.jar(browser="chrome", include_expired=True)
        self.assertIsInstance(jar, http.cookiejar.CookieJar)
        self.assertGreater(len(list(jar)), 0)

    def test_read_decrypt_failed_warning_uses_code_not_message(self) -> None:
        import sqlite3

        with _synthetic_home() as home:
            root = _chrome_root(home)
            _seed_chromium_profile(root, "Default", "plain")
            database = root / "Default" / "Network" / "Cookies"
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "INSERT INTO cookies VALUES ('.example.test', '/', 0, 0, 'secret', '', ?, 0, 0)",
                    (_UNDECRYPTABLE,),
                )
                connection.commit()
            finally:
                connection.close()
            (root / "Local State").write_text("{}", encoding="utf-8")
            result = rookie_cookies.read(browser="chrome", include_expired=True)
        warning = next(item for item in result.warnings if item.code == "decrypt_failed")
        self.assertEqual(warning.count, 1)
        names = {row["name"] for row in result.as_list()}
        self.assertIn("session", names)

    def test_from_path_invalid_octets_warning_uses_code_not_message(self) -> None:
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "cookies.sqlite"
            connection = sqlite3.connect(str(db))
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
                connection.execute(
                    "INSERT INTO moz_cookies VALUES ('.example.test', '/', 0, 4102444800, ?, 'x', 0, 0)",
                    ("sid\r",),
                )
                connection.commit()
            finally:
                connection.close()
            result = rookie_cookies.from_path(str(db), include_expired=True)
        warning = next(item for item in result.warnings if item.code == "invalid_octets")
        self.assertEqual(warning.count, 1)
        self.assertEqual(len(result), 0)

    def test_header_invalid_url_exposes_structured_request_error(self) -> None:
        import sqlite3
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "cookies.sqlite"
            connection = sqlite3.connect(str(db))
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
                connection.commit()
            finally:
                connection.close()
            result = rookie_cookies.from_path(str(db), include_expired=True)

        with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
            result.header("not a url")
        self.assertEqual(raised.exception.kind, "request")
        self.assertEqual(raised.exception.code, "invalid_url")
        self.assertIsNone(raised.exception.stop_reason)

    def test_unknown_browser_is_request_error(self) -> None:
        with _synthetic_home():
            with self.assertRaises(rookie_cookies.RookieRequestError):
                rookie_cookies.read(browser="not-a-browser")
            with self.assertRaises(rookie_cookies.RookieRequestError):
                rookie_cookies.profiles("not-a-browser")
            with self.assertRaises(rookie_cookies.RookieRequestError):
                rookie_cookies.report("not-a-browser")

    def test_header_is_exactly_the_send_view_header(self) -> None:
        """Two entry points, one selection -- they cannot answer differently."""
        with tempfile.TemporaryDirectory() as temp:
            database = _seed_partitioned_gecko(Path(temp) / "cookies.sqlite")
            snapshot = rookie_cookies.from_path(str(database), include_expired=True)

        context = {
            "url": "https://embedded.example.test/",
            "top_level_site": "https://top.example.test",
            "user_context_id": 0,
            "private_browsing_id": 0,
            "first_party_domain": "",
            "gecko_view_session_context_id": "",
        }
        view = snapshot.send_view(context)
        self.assertEqual(snapshot.header(context), view["header"])
        # The header is the selected rows, not a separate render of the
        # snapshot: it names every selected cookie and nothing else.
        self.assertEqual(
            view["header"],
            "; ".join(
                f"{record['cookie']['name']}={record['cookie']['value']}"
                for record in view["cookies"]
            ),
        )
        # Every reason is present, so indexing one needs no guard.
        self.assertEqual(
            set(view["omitted"]),
            {
                "expired",
                "not_applicable",
                "same_site",
                "partition",
                "ancestor_chain_unknown",
                "unparsable_partition_key",
                "origin",
            },
        )

    def test_as_jar_refuses_an_isolated_snapshot_and_says_what_to_supply(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            database = _seed_partitioned_gecko(Path(temp) / "cookies.sqlite")
            snapshot = rookie_cookies.from_path(str(database), include_expired=True)

        with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
            snapshot.as_jar()
        self.assertEqual(raised.exception.kind, "request")
        self.assertEqual(raised.exception.code, "isolation_loss_refused")
        # The refusal is only useful if it names the way forward, and it uses
        # the same token vocabulary `incomplete_send_context` does. Only
        # `top_level_site` here: every container dimension in this store holds
        # its default, and a default never demands a selector. The
        # longer vocabularies live in `test_isolation_corpus.py`.
        self.assertEqual(list(raised.exception.required), ["top_level_site"])
        with self.assertRaises(rookie_cookies.RookieRequestError) as demanded:
            snapshot.send_view("https://embedded.example.test/")
        self.assertEqual(demanded.exception.code, "incomplete_send_context")
        self.assertEqual(
            list(demanded.exception.required), list(raised.exception.required)
        )

        # The inventory projection is unaffected: it never promised send
        # safety, so it does not refuse.
        self.assertGreater(len(snapshot.as_list()), 0)
        opted_in = snapshot.as_jar(allow_isolation_loss=True)
        self.assertIsInstance(opted_in, http.cookiejar.CookieJar)
        self.assertEqual(len(list(opted_in)), len(snapshot.as_list()))

    def test_profiles_aliases_browser_profiles(self) -> None:
        with _synthetic_home() as home:
            _seed_chrome(home)
            self.assertEqual(
                rookie_cookies.profiles("chrome"),
                rookie_cookies.browser_profiles("chrome"),
            )


if __name__ == "__main__":
    unittest.main()
