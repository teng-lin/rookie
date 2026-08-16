from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run-consumer-harness.py"


def write_manifest(path: Path, artifacts_root: Path, artifact_paths: list[Path]) -> None:
    records = []
    for artifact_path in artifact_paths:
        data = artifact_path.read_bytes()
        records.append(
            {
                "path": str(artifact_path.relative_to(artifacts_root)),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    path.write_text(
        json.dumps({"schema_version": 2, "release": {"version": "0.5.9"}, "artifacts": records}),
        encoding="utf-8",
    )


def make_npm_tarball(
    path: Path,
    *,
    name: str,
    os_tags: list[str] | None = None,
    cpu_tags: list[str] | None = None,
    main: str = "index.js",
) -> None:
    with tempfile.TemporaryDirectory() as staging:
        staging_path = Path(staging)
        package_dir = staging_path / "package"
        package_dir.mkdir()
        package_json: dict[str, object] = {"name": name, "version": "1.0.0", "main": main}
        if os_tags is not None:
            package_json["os"] = os_tags
        if cpu_tags is not None:
            package_json["cpu"] = cpu_tags
        (package_dir / "package.json").write_text(json.dumps(package_json), encoding="utf-8")
        (package_dir / main).write_text("module.exports = {};", encoding="utf-8")
        with tarfile.open(path, "w:gz") as tar:
            tar.add(package_dir, arcname="package")


class ConsumerHarnessTests(unittest.TestCase):
    def run_harness(self, artifacts_root: Path, manifest_path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(manifest_path),
                "--artifacts-root",
                str(artifacts_root),
            ],
            capture_output=True,
            text=True,
        )

    def test_verifies_and_structurally_checks_a_platform_agnostic_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("structurally verified: rookie-cookies@1.0.0", result.stdout)

    def test_reports_checksum_only_for_a_foreign_platform_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-win32-x64-msvc-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies-win32-x64-msvc", os_tags=["win32"])
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checksum-verified only", result.stdout)

    def test_reports_checksum_only_for_a_same_os_wrong_cpu_tarball(self) -> None:
        # Same OS as the host, but the *other* CPU architecture — the os-only
        # check alone would wrongly call this compatible.
        import platform as platform_module

        wrong_cpu = "arm64" if platform_module.machine().lower() in ("x86_64", "amd64") else "x64"
        host_os = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}[platform_module.system()]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-other-arch-1.0.0.tgz"
            make_npm_tarball(
                tarball,
                name="rookie-cookies-other-arch",
                os_tags=[host_os],
                cpu_tags=[wrong_cpu],
            )
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checksum-verified only", result.stdout)
            self.assertNotIn("structurally verified", result.stdout)

    def test_fails_closed_on_a_sha256_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            tarball.write_bytes(tarball.read_bytes() + b"tampered")

            result = self.run_harness(root, manifest_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 mismatch", result.stderr)

    def test_fails_closed_on_a_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            tarball.unlink()

            result = self.run_harness(root, manifest_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing artifact", result.stderr)

    def test_fails_closed_when_main_entry_is_absent_from_the_tarball(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            with tempfile.TemporaryDirectory() as staging:
                staging_path = Path(staging)
                package_dir = staging_path / "package"
                package_dir.mkdir()
                (package_dir / "package.json").write_text(
                    json.dumps({"name": "rookie-cookies", "version": "1.0.0", "main": "missing.js"}),
                    encoding="utf-8",
                )
                with tarfile.open(tarball, "w:gz") as tar:
                    tar.add(package_dir, arcname="package")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            result = self.run_harness(root, manifest_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not exist in the tarball", result.stderr)

    def test_native_addon_is_checksum_verified_but_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            addon = root / "rookie_cookies.win32-x64-msvc.node"
            addon.write_bytes(b"not-a-real-binary")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [addon])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checksum-verified only", result.stdout)


if __name__ == "__main__":
    unittest.main()
