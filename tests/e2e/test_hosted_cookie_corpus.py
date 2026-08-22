"""Unit contracts for the installed-browser portable corpus oracle."""

from __future__ import annotations

import struct
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import hosted_cookie_corpus as hosted


CONTEXT = {
    "top_frame_site_key": None,
    "has_cross_site_ancestor": None,
    "source_scheme": None,
    "source_port": None,
    "is_persistent": None,
    "origin_attributes": None,
    "user_context_id": None,
    "partition_key": None,
    "private_browsing_id": None,
}


def portable_observations(engine: str, browser: str, platform: str) -> list[dict]:
    corpus = hosted.load_corpus()
    observations = []
    now = int(time.time())
    for scenario in hosted.applicable_scenarios(corpus, engine, platform):
        if not scenario["expected"]["stored"]:
            continue
        operation = scenario["operations"][-1]
        expiry_window = hosted._expected_expiry_window(  # noqa: SLF001
            scenario, operation, browser
        )
        expires = (
            None
            if expiry_window is None
            else now + (expiry_window[0] + expiry_window[1]) // 2
        )
        observations.append(
            {
                "domain": operation.get(
                    "domain", corpus["origins"][scenario["origin"]]["hostname"]
                ),
                "path": operation.get("path", "/"),
                "name": operation["name"],
                "observed_value": hosted.expanded_value(operation),
                "secure": bool(operation.get("secure")),
                "http_only": bool(operation.get("http_only")),
                "same_site": scenario["expected"]["same_site"][engine],
                "expires": expires,
                "context": dict(CONTEXT),
            }
        )
    return observations


def safari_record() -> bytes:
    strings = b".127.0.0.1\0rookie_native\0/nested\0secret\0"
    domain = 0x30
    name = domain + len(b".127.0.0.1\0")
    path = name + len(b"rookie_native\0")
    value = path + len(b"/nested\0")
    record = bytearray(value + len(b"secret\0"))
    struct.pack_into("<I", record, 0, len(record))
    struct.pack_into("<I", record, 0x08, 0x05)
    struct.pack_into("<IIII", record, 0x10, domain, name, path, value)
    struct.pack_into(
        "<d",
        record,
        0x28,
        time.time() + 3600 - hosted.SAFARI_EPOCH_OFFSET_SECONDS,
    )
    record[0x30:] = strings
    return bytes(record)


class HostedCookieCorpusTests(unittest.TestCase):
    def test_runner_url_maps_gecko_to_firefox_and_selects_portable_tier(self) -> None:
        self.assertEqual(
            hosted.corpus_seed_url(8765, "gecko"),
            "http://127.0.0.1:8765/corpus/run?engine=firefox&tiers=portable_smoke&step=0",
        )

    def test_every_live_engine_builds_a_full_exact_manifest(self) -> None:
        cells = (
            ("chromium", "brave", "linux", 19),
            ("firefox", "librewolf", "macos", 20),
            ("safari", "safari", "macos", 19),
        )
        for engine, browser, platform, total in cells:
            with self.subTest(engine=engine, browser=browser, platform=platform):
                manifest = hosted.build_manifest(
                    engine=engine,
                    browser=browser,
                    platform=platform,
                    observations=portable_observations(engine, browser, platform),
                )
                self.assertEqual(len(manifest["expected"]["unfiltered_flat"]), total)
                self.assertEqual(len(manifest["expected"]["filtered_flat"]), total - 1)
                self.assertEqual(len(manifest["expected"]["detailed"]), total)
                self.assertEqual(
                    {row["name"] for row in manifest["expected"]["filtered_flat"]},
                    {
                        row["name"]
                        for row in manifest["expected"]["unfiltered_flat"]
                        if row["name"] != "rookie_decoy"
                    },
                )

    def test_unexpected_target_origin_cookie_is_rejected(self) -> None:
        observations = portable_observations("chromium", "edge", "windows")
        observations.append(
            {
                **observations[0],
                "name": "unexpected_leak",
                "observed_value": "must-fail",
            }
        )
        with self.assertRaisesRegex(
            hosted.HostedCorpusError, "unexpected target-domain cookies"
        ):
            hosted.build_manifest(
                engine="chromium",
                browser="edge",
                platform="windows",
                observations=observations,
            )

    def test_chromium_reader_uses_raw_metadata_but_not_ciphertext_as_value(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "Cookies"
            connection = sqlite3.connect(database)
            connection.execute(
                """
                create table cookies (
                  host_key text, path text, name text, value text,
                  encrypted_value blob, is_secure integer, is_httponly integer,
                  samesite integer, expires_utc integer,
                  top_frame_site_key text, has_cross_site_ancestor integer,
                  source_scheme integer, source_port integer, is_persistent integer
                )
                """
            )
            connection.execute(
                "insert into cookies values "
                "('127.0.0.1', '/nested', 'rookie_raw', '', X'76313001', "
                "1, 1, 2, ?, 'https://top.test', 1, 2, 443, 1)",
                (hosted.CHROMIUM_EPOCH_OFFSET_US + 4_102_444_800_000_000,),
            )
            connection.commit()
            connection.close()
            observation = hosted.read_observations("chromium", database)[0]
        self.assertIsNone(observation["observed_value"])
        self.assertEqual(observation["expires"], 4_102_444_800)
        self.assertEqual(observation["context"]["source_scheme"], 2)
        self.assertEqual(observation["context"]["source_port"], 443)
        self.assertTrue(observation["context"]["has_cross_site_ancestor"])

    def test_firefox_reader_normalizes_current_millisecond_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "cookies.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("pragma user_version=17")
            connection.execute(
                "create table moz_cookies (host text, path text, name text, "
                "value text, isSecure integer, isHttpOnly integer, sameSite integer, "
                "expiry integer, originAttributes text)"
            )
            connection.execute(
                "insert into moz_cookies values "
                "('.127.0.0.1', '/', 'rookie_raw', 'visible', 0, 1, 1, "
                "4102444800000, '^partitionKey=%28https%2Ctop.test%29')"
            )
            connection.commit()
            connection.close()
            observation = hosted.read_observations("firefox", database)[0]
        self.assertEqual(observation["observed_value"], "visible")
        self.assertEqual(observation["expires"], 4_102_444_800)
        self.assertIn("partitionKey", observation["context"]["origin_attributes"])

    def test_safari_binary_parser_reads_flags_strings_and_epoch(self) -> None:
        record = safari_record()
        page = bytearray(16 + len(record))
        page[:4] = b"\x00\x00\x01\x00"
        struct.pack_into("<I", page, 4, 1)
        struct.pack_into("<I", page, 8, 16)
        page[16:] = record
        image = b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page
        with tempfile.TemporaryDirectory() as temporary:
            cookie_file = Path(temporary) / "Cookies.binarycookies"
            cookie_file.write_bytes(image)
            observation = hosted.read_observations("safari", cookie_file)[0]
        self.assertEqual(observation["domain"], ".127.0.0.1")
        self.assertEqual(observation["name"], "rookie_native")
        self.assertEqual(observation["path"], "/nested")
        self.assertEqual(observation["observed_value"], "secret")
        self.assertTrue(observation["secure"])
        self.assertTrue(observation["http_only"])
        self.assertAlmostEqual(observation["expires"], int(time.time()) + 3600, delta=2)


if __name__ == "__main__":
    unittest.main()
