from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "write-release-scan-manifest.py"

JCS_SPEC = importlib.util.spec_from_file_location("jcs", ROOT / "scripts/jcs.py")
assert JCS_SPEC is not None and JCS_SPEC.loader is not None
jcs = importlib.util.module_from_spec(JCS_SPEC)
sys.modules[JCS_SPEC.name] = jcs
JCS_SPEC.loader.exec_module(jcs)


class ReleaseScanManifestTests(unittest.TestCase):
    def test_records_exact_source_and_artifact_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            # Realistic filenames -- see publish-npm.yml -- so this also
            # exercises helper_roles matching against the real contract
            # rather than a name match_cell_for_artifact can't resolve.
            scan = artifact_root / "scan" / "rookie_cookies.win32-x64-msvc.node"
            tarball = artifact_root / "rookie-cookies-win32-x64-msvc-0.5.9.tgz"
            scan.parent.mkdir(parents=True)
            scan.write_bytes(b"native-binary")
            tarball.write_bytes(b"package-tarball")
            output = artifact_root / "scan" / "release-scan-manifest.json"
            source_sha = "a" * 40
            controller_sha = "c" * 40
            contract_digest = "d" * 64

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    source_sha,
                    "--controller-sha",
                    controller_sha,
                    "--platform-contract-digest",
                    contract_digest,
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(output),
                    str(scan),
                    str(tarball),
                ],
                check=True,
            )

            manifest = json.loads(output.read_text(encoding="utf-8"))
            expected_digest = jcs.digest(
                {
                    "release": {
                        "source_sha": source_sha,
                        "controller_sha": controller_sha,
                        "platform_contract_digest": contract_digest,
                        "tag": "v0.5.9",
                        "version": "0.5.9",
                        "kind": "release",
                    },
                    "artifacts": manifest["artifacts"],
                }
            )
            self.assertEqual(
                manifest["release"],
                {
                    "source_sha": source_sha,
                    "controller_sha": controller_sha,
                    "platform_contract_digest": contract_digest,
                    "tag": "v0.5.9",
                    "version": "0.5.9",
                    "kind": "release",
                    "manifest_digest": expected_digest,
                },
            )
            self.assertEqual(manifest["schema_version"], 4)
            self.assertEqual(
                [record["path"] for record in manifest["artifacts"]],
                [
                    "rookie-cookies-win32-x64-msvc-0.5.9.tgz",
                    "scan/rookie_cookies.win32-x64-msvc.node",
                ],
            )
            self.assertEqual(
                manifest["artifacts"][1]["sha256"],
                hashlib.sha256(b"native-binary").hexdigest(),
            )
            # Both artifacts are the win32-x64-msvc npm-native cell, which
            # platform-contract.json declares with dpapi + appbound helper
            # roles.
            for record in manifest["artifacts"]:
                self.assertEqual(record["helper_roles"], ["appbound", "dpapi"])

    def test_kind_defaults_to_release_and_accepts_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            artifact_root.mkdir()
            artifact = artifact_root / "rookie-cookies-cli-x86_64-unknown-linux-gnu"
            artifact.write_bytes(b"cli-binary")
            output = artifact_root / "manifest.json"

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    "a" * 40,
                    "--controller-sha",
                    "c" * 40,
                    "--platform-contract-digest",
                    "d" * 64,
                    "--kind",
                    "candidate",
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(output),
                    str(artifact),
                ],
                check=True,
            )
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(manifest["release"]["kind"], "candidate")

            output.unlink()
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    "a" * 40,
                    "--controller-sha",
                    "c" * 40,
                    "--platform-contract-digest",
                    "d" * 64,
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(output),
                    str(artifact),
                ],
                check=True,
            )
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(manifest["release"]["kind"], "release")

    def test_manifest_digest_changes_when_an_artifact_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            artifact_root.mkdir()
            artifact = artifact_root / "rookie-cookies-cli-x86_64-unknown-linux-gnu"
            output = artifact_root / "manifest.json"
            common_args = [
                sys.executable,
                str(SCRIPT),
                "--version",
                "0.5.9",
                "--source-sha",
                "a" * 40,
                "--controller-sha",
                "c" * 40,
                "--platform-contract-digest",
                "d" * 64,
                "--root",
                str(artifact_root),
                "--output",
                str(output),
                str(artifact),
            ]

            artifact.write_bytes(b"first-build")
            subprocess.run(common_args, check=True)
            first_digest = json.loads(output.read_text(encoding="utf-8"))["release"][
                "manifest_digest"
            ]

            output.unlink()
            artifact.write_bytes(b"different-build")
            subprocess.run(common_args, check=True)
            second_digest = json.loads(output.read_text(encoding="utf-8"))["release"][
                "manifest_digest"
            ]

            self.assertNotEqual(first_digest, second_digest)

    def test_rejects_artifacts_outside_the_manifest_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            artifact_root = base / "release"
            artifact_root.mkdir()
            outside = base / "outside.bin"
            outside.write_bytes(b"outside")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    "b" * 40,
                    "--controller-sha",
                    "c" * 40,
                    "--platform-contract-digest",
                    "d" * 64,
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(artifact_root / "manifest.json"),
                    str(outside),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("outside manifest root", result.stderr)

    def test_rejects_a_malformed_controller_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            artifact_root.mkdir()
            artifact = artifact_root / "a.bin"
            artifact.write_bytes(b"x")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    "a" * 40,
                    "--controller-sha",
                    "not-a-sha",
                    "--platform-contract-digest",
                    "d" * 64,
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(artifact_root / "manifest.json"),
                    str(artifact),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("controller SHA", result.stderr)

    def test_rejects_a_malformed_platform_contract_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            artifact_root.mkdir()
            artifact = artifact_root / "a.bin"
            artifact.write_bytes(b"x")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    "a" * 40,
                    "--controller-sha",
                    "c" * 40,
                    "--platform-contract-digest",
                    "too-short",
                    "--root",
                    str(artifact_root),
                    "--output",
                    str(artifact_root / "manifest.json"),
                    str(artifact),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("platform contract digest", result.stderr)


if __name__ == "__main__":
    unittest.main()
