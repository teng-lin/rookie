from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_release", REPOSITORY_ROOT / "scripts/check-release.py"
)
assert SPEC is not None and SPEC.loader is not None
check_release = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_release
SPEC.loader.exec_module(check_release)


class SemverPrecedenceKeyTests(unittest.TestCase):
    def test_orders_release_versions_numerically(self) -> None:
        self.assertLess(
            check_release.semver_precedence_key("0.5.9"),
            check_release.semver_precedence_key("0.5.10"),
        )
        self.assertLess(
            check_release.semver_precedence_key("0.9.0"),
            check_release.semver_precedence_key("0.10.0"),
        )
        self.assertLess(
            check_release.semver_precedence_key("0.5.9"),
            check_release.semver_precedence_key("1.0.0"),
        )

    def test_release_outranks_any_prerelease_of_the_same_core(self) -> None:
        self.assertLess(
            check_release.semver_precedence_key("1.0.0-rc.1"),
            check_release.semver_precedence_key("1.0.0"),
        )

    def test_numeric_prerelease_identifiers_outrank_none_but_rank_below_alphanumeric(
        self,
    ) -> None:
        self.assertLess(
            check_release.semver_precedence_key("1.0.0-1"),
            check_release.semver_precedence_key("1.0.0-alpha"),
        )

    def test_more_prerelease_fields_outrank_fewer_when_prefix_equal(self) -> None:
        self.assertLess(
            check_release.semver_precedence_key("1.0.0-alpha"),
            check_release.semver_precedence_key("1.0.0-alpha.1"),
        )

    def test_rejects_non_semver_input(self) -> None:
        with self.assertRaises(ValueError):
            check_release.semver_precedence_key("not-a-version")


class LatestPublishedVersionTests(unittest.TestCase):
    def _init_repo_with_tags(self, tags: list[str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        subprocess.run(
            ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit",
             "--allow-empty", "--quiet", "-m", "init"],
            cwd=root,
            check=True,
        )
        for tag in tags:
            subprocess.run(["git", "tag", tag], cwd=root, check=True)
        return root

    def test_returns_none_with_no_tags(self) -> None:
        root = self._init_repo_with_tags([])
        self.assertIsNone(check_release.latest_published_version(root, excluding="1.0.0"))

    def test_returns_highest_semver_tag(self) -> None:
        root = self._init_repo_with_tags(["v0.5.7", "v0.5.9", "v0.5.8"])
        self.assertEqual(
            check_release.latest_published_version(root, excluding="9.9.9"), "0.5.9"
        )

    def test_excludes_the_version_being_released(self) -> None:
        # The release workflow's own tag already exists by the time this
        # check runs; it must not count as "previously published".
        root = self._init_repo_with_tags(["v0.5.8", "v0.5.9"])
        self.assertEqual(
            check_release.latest_published_version(root, excluding="0.5.9"), "0.5.8"
        )

    def test_ignores_non_semver_and_non_v_prefixed_tags(self) -> None:
        root = self._init_repo_with_tags(["v0.5.8", "not-a-release", "release-marker"])
        self.assertEqual(
            check_release.latest_published_version(root, excluding="9.9.9"), "0.5.8"
        )


class ChangelogSectionTests(unittest.TestCase):
    def test_extracts_release_prose_until_the_next_release(self) -> None:
        document = (
            "## [Unreleased]\n\n## [0.6.0] - 2026-08-21\n\n"
            "### Added\n\n- Stable summary.\n\n## [0.5.9] - 2026-08-15\n"
        )
        heading = check_release.re.search(r"^## \[0\.6\.0\].*$", document, flags=check_release.re.MULTILINE)
        self.assertIsNotNone(heading)
        assert heading is not None
        self.assertEqual(
            check_release.section_body(document, heading.end()).strip(),
            "### Added\n\n- Stable summary.",
        )

    def test_empty_release_body_is_detectable(self) -> None:
        document = "## [0.6.0] - 2026-08-21\n\n## [0.5.9] - 2026-08-15\n"
        heading = check_release.re.search(r"^## \[0\.6\.0\].*$", document, flags=check_release.re.MULTILINE)
        self.assertIsNotNone(heading)
        assert heading is not None
        self.assertFalse(check_release.section_body(document, heading.end()).strip())


if __name__ == "__main__":
    unittest.main()
