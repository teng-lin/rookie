from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "record-scan-disposition.py"


def write_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "release": {"source_sha": "a" * 40, "controller_sha": "a" * 40, "version": "0.5.9"},
                "artifacts": [
                    {"path": "scan/rookie_cookies.win32-x64-msvc.node", "bytes": 5, "sha256": "b" * 64},
                    {"path": "rookie-cookies-1.0.0.tgz", "bytes": 5, "sha256": "c" * 64},
                ],
            }
        ),
        encoding="utf-8",
    )


class RecordScanDispositionTests(unittest.TestCase):
    def test_records_a_clean_result_bound_to_the_artifacts_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifact",
                    "scan/rookie_cookies.win32-x64-msvc.node",
                    "--scanner-product",
                    "ESET Endpoint Antivirus",
                    "--scanner-engine-version",
                    "1.2.3",
                    "--scanner-signature-version",
                    "30000",
                    "--result",
                    "clean",
                    "--reviewer",
                    "teng-lin",
                    "--timestamp",
                    "2026-08-16T12:00:00Z",
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["scan_evidence"]), 1)
            entry = manifest["scan_evidence"][0]
            self.assertEqual(entry["artifact_sha256"], "b" * 64)
            self.assertEqual(entry["result"], "clean")
            self.assertIsNone(entry["detection_name"])
            self.assertEqual(entry["reviewer"], "teng-lin")

    def test_appends_rather_than_overwrites_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)
            base_args = [
                sys.executable,
                str(SCRIPT),
                "--manifest",
                str(manifest_path),
                "--artifact",
                "rookie-cookies-1.0.0.tgz",
                "--scanner-product",
                "ESET",
                "--scanner-engine-version",
                "1",
                "--scanner-signature-version",
                "1",
                "--result",
                "clean",
                "--reviewer",
                "a",
                "--timestamp",
                "2026-08-16T12:00:00Z",
            ]
            subprocess.run(base_args, check=True, capture_output=True, text=True)
            subprocess.run(base_args, check=True, capture_output=True, text=True)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest["scan_evidence"]), 2)

    def test_detected_result_requires_a_detection_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifact",
                    "scan/rookie_cookies.win32-x64-msvc.node",
                    "--scanner-product",
                    "ESET",
                    "--scanner-engine-version",
                    "1",
                    "--scanner-signature-version",
                    "1",
                    "--result",
                    "detected",
                    "--reviewer",
                    "a",
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--detection-name is required", result.stderr)

    def test_clean_result_rejects_a_detection_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifact",
                    "scan/rookie_cookies.win32-x64-msvc.node",
                    "--scanner-product",
                    "ESET",
                    "--scanner-engine-version",
                    "1",
                    "--scanner-signature-version",
                    "1",
                    "--result",
                    "clean",
                    "--detection-name",
                    "Win32/Whatever",
                    "--reviewer",
                    "a",
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not be set", result.stderr)

    def test_unknown_artifact_path_fails_with_available_paths_listed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifact",
                    "nonexistent.bin",
                    "--scanner-product",
                    "ESET",
                    "--scanner-engine-version",
                    "1",
                    "--scanner-signature-version",
                    "1",
                    "--result",
                    "clean",
                    "--reviewer",
                    "a",
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("is not an artifact in this manifest", result.stderr)

    def test_rejects_a_malformed_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            write_manifest(manifest_path)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifact",
                    "rookie-cookies-1.0.0.tgz",
                    "--scanner-product",
                    "ESET",
                    "--scanner-engine-version",
                    "1",
                    "--scanner-signature-version",
                    "1",
                    "--result",
                    "clean",
                    "--reviewer",
                    "a",
                    "--timestamp",
                    "not-a-timestamp",
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not ISO-8601", result.stderr)


if __name__ == "__main__":
    unittest.main()
