from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "bump_version", REPOSITORY_ROOT / "scripts/bump-version.py"
)
assert SPEC is not None and SPEC.loader is not None
bump_version = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bump_version
SPEC.loader.exec_module(bump_version)


class VersionValidationTests(unittest.TestCase):
    def test_accepts_semver(self) -> None:
        for version in ("0.5.10", "1.2.3-alpha.1", "1.2.3-rc.1+build.5"):
            with self.subTest(version=version):
                self.assertEqual(bump_version.validate_semver(version), version)

    def test_rejects_invalid_semver(self) -> None:
        for version in ("1.2", "01.2.3", "1.2.3-01", "1.2.3-", "1.2.3+"):
            with self.subTest(version=version):
                with self.assertRaises(bump_version.ReleaseError):
                    bump_version.validate_semver(version)

    def test_rejects_invalid_release_dates(self) -> None:
        for release_date in ("2026-02-30", "08/20/2026", "2026-8-20"):
            with self.subTest(release_date=release_date):
                with self.assertRaises(bump_version.ReleaseError):
                    bump_version.validate_date(release_date)


class StructuralUpdateTests(unittest.TestCase):
    def test_toml_update_does_not_touch_unrelated_matching_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text(
                """\
[workspace.package]
version = "0.5.9"

[workspace.dependencies.unrelated]
version = "0.5.9"
""",
                encoding="utf-8",
            )

            change = bump_version.update_toml_string(
                manifest, ("workspace", "package"), "version", "0.5.10"
            )

            self.assertIsNotNone(change)
            parsed = bump_version.load_toml(manifest)
            self.assertEqual(parsed["workspace"]["package"]["version"], "0.5.10")
            self.assertEqual(
                parsed["workspace"]["dependencies"]["unrelated"]["version"],
                "0.5.9",
            )

    def test_json_update_does_not_touch_unrelated_matching_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "package.json"
            manifest.write_text(
                json.dumps(
                    {
                        "name": "rookie-cookies",
                        "version": "0.5.9",
                        "devDependencies": {"unrelated": "0.5.9"},
                    }
                ),
                encoding="utf-8",
            )

            bump_version.update_json_strings(
                manifest, {("version",): "0.5.10"}
            )

            parsed = bump_version.load_json(manifest)
            self.assertEqual(parsed["version"], "0.5.10")
            self.assertEqual(parsed["devDependencies"]["unrelated"], "0.5.9")

    def test_native_lock_normalization_preserves_unrelated_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"version": "0.5.10"},
                            "node_modules/unrelated": {"version": "0.5.9"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            bump_version.normalize_native_lock_records(lockfile, "0.5.10")

            packages = bump_version.load_json(lockfile)["packages"]
            self.assertEqual(packages["node_modules/unrelated"]["version"], "0.5.9")
            for package_name in bump_version.NATIVE_PACKAGES:
                self.assertEqual(
                    packages[f"node_modules/{package_name}"],
                    {"version": "0.5.10", "optional": True},
                )

    def test_native_lock_normalization_preserves_sri_for_the_target_version(self) -> None:
        pinned_package = f"node_modules/{bump_version.NATIVE_PACKAGES[0]}"
        pinned_record = {
            "version": "0.5.10",
            "resolved": "https://registry.npmjs.org/...-0.5.10.tgz",
            "integrity": "sha512-already-pinned==",
            "optional": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {"": {"version": "0.5.10"}, pinned_package: pinned_record},
                    }
                ),
                encoding="utf-8",
            )

            bump_version.normalize_native_lock_records(lockfile, "0.5.10")

            packages = bump_version.load_json(lockfile)["packages"]
            self.assertEqual(packages[pinned_package], pinned_record)

    def test_native_lock_normalization_drops_sri_for_a_different_version(self) -> None:
        pinned_package = f"node_modules/{bump_version.NATIVE_PACKAGES[0]}"
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "package-lock.json"
            lockfile.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {"version": "0.5.11"},
                            pinned_package: {
                                "version": "0.5.10",
                                "resolved": "https://registry.npmjs.org/...-0.5.10.tgz",
                                "integrity": "sha512-stale==",
                                "optional": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            bump_version.normalize_native_lock_records(lockfile, "0.5.11")

            packages = bump_version.load_json(lockfile)["packages"]
            self.assertEqual(packages[pinned_package], {"version": "0.5.11", "optional": True})


class ChangelogTests(unittest.TestCase):
    def write_changelog(self, directory: str, text: str) -> Path:
        path = Path(directory) / "CHANGELOG.md"
        path.write_text(text, encoding="utf-8")
        return path

    def test_promotes_authored_unreleased_prose(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_changelog(
                directory,
                "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Human prose.\n\n## [0.5.9] - 2026-08-15\n",
            )

            bump_version.update_changelog(
                path, "0.5.9", "0.5.10", "2026-08-20", True
            )

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                "# Changelog\n\n## [Unreleased]\n\n## [0.5.10] - 2026-08-20\n\n### Added\n\n- Human prose.\n\n## [0.5.9] - 2026-08-15\n",
            )

    def test_rerun_of_prepared_current_version_is_a_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text = "# Changelog\n\n## [Unreleased]\n\n## [0.5.10] - 2026-08-20\n"
            path = self.write_changelog(directory, text)

            change = bump_version.update_changelog(
                path, "0.5.10", "0.5.10", "2026-08-20", True
            )

            self.assertIsNone(change)
            self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_rejects_duplicate_unreleased_sections_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text = "# Changelog\n\n## [Unreleased]\n\n## [Unreleased]\n"
            path = self.write_changelog(directory, text)

            with self.assertRaisesRegex(
                bump_version.ReleaseError, "exactly one.*Unreleased"
            ):
                bump_version.update_changelog(
                    path, "0.5.9", "0.5.10", "2026-08-20", True
                )

            self.assertEqual(path.read_text(encoding="utf-8"), text)

    def test_rejects_an_existing_target_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_changelog(
                directory,
                "# Changelog\n\n## [Unreleased]\n\n## [0.5.10] - 2026-08-20\n\n## [0.5.9] - 2026-08-15\n",
            )

            with self.assertRaisesRegex(
                bump_version.ReleaseError, "release heading.*already exists"
            ):
                bump_version.update_changelog(
                    path, "0.5.9", "0.5.10", "2026-08-20", True
                )

    def test_rejects_new_prose_when_current_version_is_already_released(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_changelog(
                directory,
                "# Changelog\n\n## [Unreleased]\n\n- A later change.\n\n## [0.5.10] - 2026-08-20\n",
            )

            with self.assertRaisesRegex(
                bump_version.ReleaseError, "Unreleased contains new prose"
            ):
                bump_version.update_changelog(
                    path, "0.5.10", "0.5.10", "2026-08-20", True
                )


class RollbackTests(unittest.TestCase):
    def test_package_manager_failure_restores_every_managed_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                """\
[workspace.package]
version = "0.5.9"

[workspace.dependencies.rookie-cookies]
path = "rookie-rs"
version = "0.5.9"
default-features = false
""",
                encoding="utf-8",
            )
            (root / "CHANGELOG.md").write_text(
                "# Changelog\n\n## [Unreleased]\n\n- Human prose.\n\n## [0.5.9] - 2026-08-15\n",
                encoding="utf-8",
            )
            root_manifest = {
                "name": "rookie-cookies",
                "version": "0.5.9",
                "optionalDependencies": {
                    package_name: "0.5.9"
                    for package_name in bump_version.NATIVE_PACKAGES
                },
            }
            (root / "bindings/node").mkdir(parents=True)
            (root / "bindings/node/package.json").write_text(
                json.dumps(root_manifest), encoding="utf-8"
            )
            for relative in bump_version.NATIVE_MANIFESTS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps({"version": "0.5.9"}), encoding="utf-8"
                )
            for relative in (
                Path("Cargo.lock"),
                Path("bindings/node/package-lock.json"),
                Path("examples/javascript/package-lock.json"),
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"unchanged {relative}\n", encoding="utf-8")
            before = {
                relative: (root / relative).read_bytes()
                for relative in bump_version.MANAGED_PATHS
            }

            with (
                mock.patch.object(bump_version, "verify_release"),
                mock.patch.object(
                    bump_version,
                    "regenerate_lockfiles",
                    side_effect=bump_version.ReleaseError("npm failed"),
                ),
            ):
                with self.assertRaisesRegex(
                    bump_version.ReleaseError, "rolled back.*npm failed"
                ):
                    bump_version.bump_version(
                        root, "0.5.10", "2026-08-20", True
                    )

            after = {
                relative: (root / relative).read_bytes()
                for relative in bump_version.MANAGED_PATHS
            }
            self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
