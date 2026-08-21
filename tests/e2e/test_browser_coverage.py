"""Every registry browser/OS pair must appear in the claimed-browser matrix."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
REGISTRY_PATH = REPOSITORY_ROOT / "rookie-rs" / "browser_registry.json"
TESTING_MD_PATH = REPOSITORY_ROOT / "docs" / "testing.md"
sys.path.insert(0, str(Path(__file__).parent))

from browser_coverage_contract import DEPTH_LEVELS, assert_observed_depth, depth_for

# docs/testing.md uses the shorter product names readers already know.
DOC_BROWSER_TITLES = {
    "chrome": "Chrome",
    "coccoc": "Cốc Cốc",
    "edge": "Edge",
}
DOC_LANE_CELLS = {
    "hosted": "nightly_hosted",
    "fixture": "release_fixture",
    "manual": "manual",
    "**manual**": "manual",
    "—": None,
}

KNOWN_LANES = frozenset({"nightly_hosted", "release_fixture", "manual"})
COOKIE_CONTEXT_FIELDS = frozenset(
    {
        "top_frame_site_key",
        "has_cross_site_ancestor",
        "source_scheme",
        "source_port",
        "is_persistent",
        "origin_attributes",
        "user_context_id",
        "partition_key",
        "private_browsing_id",
    }
)
CONTEXT_CLASSIFICATIONS = frozenset(
    {"live", "fixture_only", "non_persistable"}
)
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
        ("macos", "brave"),
        ("macos", "chrome"),
        ("macos", "chromium"),
        ("macos", "edge"),
        ("macos", "firefox"),
        ("macos", "librewolf"),
        ("macos", "opera"),
        ("macos", "opera_gx"),
        ("macos", "safari"),
        ("macos", "vivaldi"),
        ("macos", "yandex"),
        ("macos", "zen"),
        ("windows", "brave"),
        ("windows", "chrome"),
        ("windows", "chromium"),
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
MANUAL: frozenset[tuple[str, str]] = frozenset()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _doc_title(canonical_id: str, display_name: str) -> str:
    return DOC_BROWSER_TITLES.get(canonical_id, display_name)


def _parse_testing_md_matrix(text: str) -> dict[str, dict[str, str | None]]:
    """Parse the Browser / Linux / macOS / Windows table in docs/testing.md."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith("| Browser | Linux | macOS | Windows |"):
            start = index
            break
    if start is None:
        raise AssertionError("docs/testing.md is missing the browser coverage matrix")

    rows: dict[str, dict[str, str | None]] = {}
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4:
            raise AssertionError(f"unexpected matrix row: {line!r}")
        title, *platforms = cells
        parsed: dict[str, str | None] = {}
        for platform, cell in zip(
            ("linux", "macos", "windows"), platforms, strict=True
        ):
            if cell not in DOC_LANE_CELLS:
                raise AssertionError(f"unknown lane cell {cell!r} for {title}")
            parsed[platform] = DOC_LANE_CELLS[cell]
        rows[title] = parsed
    return rows


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
        self.assertEqual(self.coverage_doc["schema_version"], 2)
        self.assertEqual(set(self.coverage_doc["lanes"]), set(KNOWN_LANES))

    def test_depth_profiles_are_complete_and_use_known_levels(self) -> None:
        capabilities = set(self.coverage_doc["depth_capabilities"])
        self.assertEqual(
            set(self.coverage_doc["depth_levels"]), set(DEPTH_LEVELS)
        )
        self.assertGreaterEqual(len(capabilities), 9)
        used_profiles = {row["depth_profile"] for row in self.coverage_doc["coverage"]}
        self.assertEqual(used_profiles, set(self.coverage_doc["depth_profiles"]))
        for name, profile in self.coverage_doc["depth_profiles"].items():
            self.assertEqual(set(profile), capabilities, name)
            for capability, level in profile.items():
                self.assertIn(level, DEPTH_LEVELS, (name, capability))

    def test_depth_profiles_do_not_overclaim_lane_provenance(self) -> None:
        for row in self.coverage_doc["coverage"]:
            depth = depth_for(row, self.coverage_doc)
            if row["lane"] == "nightly_hosted":
                self.assertNotIn("fixture", set(depth.values()), row)
                self.assertEqual(depth["browser_launch"], "live", row)
            else:
                self.assertNotIn("live", set(depth.values()), row)
                self.assertEqual(depth["browser_launch"], "none", row)

    def test_runner_contract_rejects_unobserved_depth_claims(self) -> None:
        row = next(
            row
            for row in self.coverage_doc["coverage"]
            if row["depth_profile"] == "hosted_chromium"
        )
        declared = depth_for(row, self.coverage_doc)
        observed = {
            capability: level
            for capability, level in declared.items()
            if level != "none"
        }
        assert_observed_depth(row, observed, self.coverage_doc)
        observed.pop("recommended_read")
        with self.assertRaisesRegex(AssertionError, "recommended_read"):
            assert_observed_depth(row, observed, self.coverage_doc)

    def test_every_cookie_context_field_has_an_applicability_classification(self) -> None:
        fields = self.coverage_doc["cookie_context_fields"]
        self.assertEqual(set(fields), set(COOKIE_CONTEXT_FIELDS))
        for field, contract in fields.items():
            self.assertEqual(
                set(contract), {"classification", "engines", "rationale"}, field
            )
            self.assertIn(
                contract["classification"], CONTEXT_CLASSIFICATIONS, field
            )
            self.assertTrue(contract["engines"], field)
            self.assertTrue(
                set(contract["engines"]) <= {"chromium", "gecko"}, field
            )
            self.assertGreaterEqual(len(contract["rationale"].split()), 8, field)

    def test_private_browsing_is_the_only_non_persistable_context_field(self) -> None:
        fields = self.coverage_doc["cookie_context_fields"]
        non_persistable = {
            field
            for field, contract in fields.items()
            if contract["classification"] == "non_persistable"
        }
        self.assertEqual(non_persistable, {"private_browsing_id"})

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

    def test_every_fixture_cell_has_a_concrete_limitation(self) -> None:
        fixtures = {
            f"{row['platform']}/{row['browser']}"
            for row in self.coverage_doc["coverage"]
            if row["lane"] == "release_fixture"
        }
        limitations = self.coverage_doc["fixture_limitations"]
        self.assertEqual(set(limitations), fixtures)
        for cell, reason in limitations.items():
            self.assertIsInstance(reason, str, cell)
            self.assertGreaterEqual(len(reason.split()), 6, cell)

    def test_testing_md_matrix_matches_coverage(self) -> None:
        titles: dict[str, str] = {}
        for browsers in self.registry["platforms"].values():
            for browser in browsers:
                titles[browser["canonical_id"]] = _doc_title(
                    browser["canonical_id"], browser["display_name"]
                )

        expected: dict[str, dict[str, str | None]] = {
            title: {"linux": None, "macos": None, "windows": None}
            for title in titles.values()
        }
        for row in self.coverage_doc["coverage"]:
            expected[titles[row["browser"]]][row["platform"]] = row["lane"]

        actual = _parse_testing_md_matrix(TESTING_MD_PATH.read_text(encoding="utf-8"))
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
