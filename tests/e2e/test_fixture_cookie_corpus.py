"""Contracts for the full portable corpus used by fixture-only browser rows."""

from __future__ import annotations

import unittest

from fixture_cookie_corpus import portable_fixture_observations
from hosted_cookie_corpus import build_manifest


class FixtureCookieCorpusTests(unittest.TestCase):
    def test_every_portable_fixture_is_an_exact_multi_cookie_manifest(self) -> None:
        for engine, expected_filtered, expected_total in (
            ("chromium", 18, 19),
            ("gecko", 19, 20),
        ):
            for platform in ("linux", "macos", "windows"):
                with self.subTest(engine=engine, platform=platform):
                    observations = portable_fixture_observations(
                        engine=engine,
                        browser="fixture-browser",
                        platform=platform,
                    )
                    manifest = build_manifest(
                        engine=engine,
                        browser="fixture-browser",
                        platform=platform,
                        observations=observations,
                    )
                    self.assertEqual(
                        len(manifest["expected"]["filtered_flat"]),
                        expected_filtered,
                    )
                    self.assertEqual(
                        len(manifest["expected"]["unfiltered_flat"]),
                        expected_total,
                    )
                    self.assertEqual(
                        len(manifest["expected"]["detailed"]), expected_total
                    )

    def test_fixture_corpus_covers_attributes_collisions_and_mutation(self) -> None:
        observations = portable_fixture_observations(
            engine="chromium",
            browser="arc",
            platform="windows",
            now=1_787_387_200,
        )
        by_identity = {
            (item["domain"], item["path"], item["name"]): item for item in observations
        }
        self.assertEqual(
            by_identity[("127.0.0.1", "/a/b/c", "rookie_path_collision")][
                "observed_value"
            ],
            "nested",
        )
        self.assertTrue(
            by_identity[("127.0.0.1", "/", "rookie_http_only")]["http_only"]
        )
        self.assertEqual(
            by_identity[("127.0.0.1", "/", "rookie_updated")]["observed_value"],
            "final",
        )
        self.assertIn(("localhost", "/", "rookie_decoy"), by_identity)
        self.assertNotIn(("127.0.0.1", "/", "rookie_deleted"), by_identity)


if __name__ == "__main__":
    unittest.main()
