"""Every registry browser/OS pair must appear in the claimed-browser matrix."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
REGISTRY_PATH = REPOSITORY_ROOT / "rookie-rs" / "browser_registry.json"

KNOWN_LANES = frozenset({"nightly_hosted", "release_fixture", "manual"})
NIGHTLY_HOSTED = frozenset(
    {
        ("linux", "brave"),
        ("linux", "chrome"),
        ("linux", "chromium"),
        ("linux", "edge"),
        ("linux", "firefox"),
        ("linux", "librewolf"),
        ("linux", "opera"),
        ("linux", "vivaldi"),
        ("linux", "zen"),
        ("macos", "arc"),
        ("macos", "brave"),
        ("macos", "chrome"),
        ("macos", "chromium"),
        ("macos", "edge"),
        ("macos", "firefox"),
        ("macos", "librewolf"),
        ("macos", "opera"),
        ("macos", "opera_gx"),
        ("macos", "vivaldi"),
        ("macos", "yandex"),
        ("macos", "zen"),
        ("windows", "arc"),
        ("windows", "brave"),
        ("windows", "chrome"),
        ("windows", "chromium"),
        ("windows", "duckduckgo"),
        ("windows", "edge"),
        ("windows", "firefox"),
        ("windows", "librewolf"),
        ("windows", "opera"),
        ("windows", "opera_gx"),
        ("windows", "vivaldi"),
        ("windows", "yandex"),
        ("windows", "zen"),
    }
)
MANUAL = frozenset({("macos", "safari"), ("windows", "internet_explorer")})


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _expected_lane(platform: str, browser: str) -> str:
    key = (platform, browser)
    if key in NIGHTLY_HOSTED:
        return "nightly_hosted"
    if key in MANUAL:
        return "manual"
    return "release_fixture"


class BrowserCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coverage_doc = _load_json(COVERAGE_PATH)
        cls.registry = _load_json(REGISTRY_PATH)

    def test_schema_and_lane_docs(self) -> None:
        self.assertEqual(self.coverage_doc["schema_version"], 1)
        self.assertEqual(set(self.coverage_doc["lanes"]), set(KNOWN_LANES))

    def test_every_registry_cell_has_exactly_one_lane(self) -> None:
        expected = {}
        for platform, browsers in self.registry["platforms"].items():
            for browser in browsers:
                key = (platform, browser["canonical_id"])
                expected[key] = browser["engine"]

        actual = {}
        for row in self.coverage_doc["coverage"]:
            key = (row["platform"], row["browser"])
            self.assertNotIn(key, actual, f"duplicate coverage row for {key}")
            self.assertIn(row["lane"], KNOWN_LANES, key)
            self.assertEqual(row["lane"], _expected_lane(*key), key)
            actual[key] = row["engine"]

        self.assertEqual(set(actual), set(expected))
        for key, engine in expected.items():
            self.assertEqual(actual[key], engine, key)

    def test_hosted_real_browsers_are_on_the_nightly_lane(self) -> None:
        hosted = {
            (row["platform"], row["browser"])
            for row in self.coverage_doc["coverage"]
            if row["lane"] == "nightly_hosted"
        }
        self.assertEqual(hosted, NIGHTLY_HOSTED)


if __name__ == "__main__":
    unittest.main()
