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

    def test_corpus_route_emits_attribute_matrix_from_declaration(self) -> None:
        headers = SERVER.corpus_headers(
            "/corpus/initial?engine=chromium&tiers=portable_smoke",
            "127.0.0.1:8765",
        )
        self.assertGreater(len(headers), 10)
        self.assertIn(
            "rookie_http_only=server-only; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax",
            headers,
        )
        self.assertIn(
            "rookie_ss_none=none; Path=/; Max-Age=3600; Secure; SameSite=None",
            headers,
        )
        self.assertTrue(
            any(header.startswith("rookie_large=" + "x" * 3584) for header in headers)
        )

    def test_corpus_route_is_engine_tier_phase_and_origin_aware(self) -> None:
        deep_firefox = SERVER.corpus_headers(
            "/corpus/initial?engine=firefox&tiers=deep", "127.0.0.1:8765"
        )
        self.assertEqual(deep_firefox, [])
        deep_chromium = SERVER.corpus_headers(
            "/corpus/initial?engine=chromium&tiers=deep", "127.0.0.1:8765"
        )
        self.assertTrue(
            any(header.startswith("rookie_session=session") for header in deep_chromium)
        )
        mutation = SERVER.corpus_headers(
            "/corpus/mutate?engine=chromium&tiers=portable_smoke",
            "127.0.0.1:8765",
        )
        self.assertEqual(len(mutation), 2)
        decoy = SERVER.corpus_headers(
            "/corpus/initial?engine=chromium&tiers=portable_smoke",
            "localhost:8765",
        )
        self.assertEqual(len(decoy), 1)
        self.assertTrue(decoy[0].startswith("rookie_decoy="))

    def test_corpus_run_redirects_across_every_origin_and_phase(self) -> None:
        headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=chromium&tiers=portable_smoke&step=0",
            "127.0.0.1:8765",
        )
        self.assertGreater(len(headers), 10)
        self.assertEqual(
            redirect,
            "http://localhost:8765/corpus/run?engine=chromium&tiers=portable_smoke&step=1",
        )

        decoy_headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=chromium&tiers=portable_smoke&step=1",
            "localhost:8765",
        )
        self.assertEqual(len(decoy_headers), 1)
        self.assertEqual(
            redirect,
            "http://127.0.0.1:8765/corpus/run?engine=chromium&tiers=portable_smoke&step=2",
        )

        mutation_headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=chromium&tiers=portable_smoke&step=2",
            "127.0.0.1:8765",
        )
        self.assertEqual(len(mutation_headers), 2)
        self.assertEqual(
            redirect,
            "http://localhost:8765/corpus/run?engine=chromium&tiers=portable_smoke&step=3",
        )

        final_headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=chromium&tiers=portable_smoke&step=3",
            "localhost:8765",
        )
        self.assertEqual(final_headers, [])
        self.assertIsNone(redirect)

    def test_corpus_run_corrects_the_host_before_setting_cookies(self) -> None:
        headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=chromium&tiers=portable_smoke&step=0",
            "localhost:8765",
        )
        self.assertEqual(headers, [])
        self.assertEqual(
            redirect,
            "http://127.0.0.1:8765/corpus/run?engine=chromium&tiers=portable_smoke&step=0",
        )

    def test_corpus_run_preserves_https_across_origins(self) -> None:
        headers, redirect = SERVER.corpus_run_response(
            "/corpus/run?engine=safari&tiers=portable_smoke&step=0",
            "127.0.0.1:8765",
            scheme="https",
        )
        self.assertGreater(len(headers), 10)
        self.assertEqual(
            redirect,
            "https://localhost:8765/corpus/run?engine=safari&tiers=portable_smoke&step=1",
        )

    def test_health_and_browser_subresource_routes_never_seed_legacy_cookies(
        self,
    ) -> None:
        self.assertEqual(SERVER.Handler.cookie_headers("/"), [])
        self.assertEqual(SERVER.Handler.cookie_headers("/favicon.ico"), [])

    def test_empty_corpus_result_does_not_fall_back_to_the_legacy_cookie(self) -> None:
        self.assertEqual(
            SERVER.corpus_headers(
                "/corpus/mutate?engine=firefox&tiers=portable_smoke",
                "localhost:8765",
            ),
            [],
        )

    def test_active_writer_baseline_has_replace_and_delete_subjects(self) -> None:
        self.assertEqual(
            SERVER.Handler.cookie_headers("/active-writer/baseline"),
            [
                "rookie_ci=before; Path=/; Max-Age=3600; SameSite=Lax",
                "rookie_remove=present; Path=/; Max-Age=3600; SameSite=Lax",
                "rookie_added=; Path=/; Max-Age=0; SameSite=Lax",
            ],
        )

    def test_active_writer_mutation_replaces_adds_and_deletes(self) -> None:
        self.assertEqual(
            SERVER.Handler.cookie_headers("/active-writer/mutate"),
            [
                "rookie_ci=after; Path=/; Max-Age=3600; SameSite=Lax",
                "rookie_added=present; Path=/; Max-Age=3600; SameSite=Lax",
                "rookie_remove=; Path=/; Max-Age=0; SameSite=Lax",
            ],
        )

    def test_active_writer_churn_rewrites_the_stable_mutated_state(self) -> None:
        headers = SERVER.Handler.cookie_headers(
            "/active-writer/churn?expiry=4102444800"
        )
        self.assertEqual(len(headers), 2)
        self.assertIn("rookie_ci=after", headers[0])
        self.assertIn("Expires=Fri, 01 Jan 2100 00:00:00 GMT", headers[0])
        self.assertIn("rookie_added=present", headers[1])

    def test_staged_wal_route_keeps_its_historical_canary_cookie(self) -> None:
        self.assertIn(
            "rookie_wal=live; Path=/; Max-Age=3600; SameSite=Lax",
            SERVER.Handler.cookie_headers("/wal"),
        )


class ClaimedE2eHelperTests(unittest.TestCase):
    def test_keychain_accounts_preserve_configured_vendor_identity(self) -> None:
        with mock.patch.dict(
            CLAIMED.os.environ, {"ROOKIE_E2E_KEYCHAIN_ACCOUNT": "Chromium"}
        ):
            self.assertEqual(CLAIMED.keychain_accounts(), ["Chromium"])

    def test_planted_keychain_item_is_noninteractive_for_hosted_browser(self) -> None:
        env = {
            "ROOKIE_E2E_KEYCHAIN_SERVICE": "Vivaldi Safe Storage",
            "ROOKIE_E2E_KEYCHAIN_ACCOUNT": "Vivaldi",
        }
        with (
            mock.patch.dict(CLAIMED.os.environ, env),
            mock.patch.object(CLAIMED.sys, "platform", "darwin"),
            mock.patch.object(CLAIMED.subprocess, "run") as run,
        ):
            CLAIMED.plant_keychain()
        add_command = run.call_args_list[1].args[0]
        self.assertIn("-A", add_command)
        self.assertIn("Vivaldi Safe Storage", add_command)

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
