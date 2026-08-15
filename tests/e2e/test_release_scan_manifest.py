from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "write-release-scan-manifest.py"


class ReleaseScanManifestTests(unittest.TestCase):
    def test_records_exact_source_and_artifact_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_root = Path(temporary) / "release"
            scan = artifact_root / "scan" / "rookie.node"
            tarball = artifact_root / "rookie.tgz"
            scan.parent.mkdir(parents=True)
            scan.write_bytes(b"native-binary")
            tarball.write_bytes(b"package-tarball")
            output = artifact_root / "scan" / "release-scan-manifest.json"
            source_sha = "a" * 40

            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--version",
                    "0.5.9",
                    "--source-sha",
                    source_sha,
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
            self.assertEqual(
                manifest["release"],
                {"source_sha": source_sha, "tag": "v0.5.9", "version": "0.5.9"},
            )
            self.assertEqual(
                [record["path"] for record in manifest["artifacts"]],
                ["rookie.tgz", "scan/rookie.node"],
            )
            self.assertEqual(
                manifest["artifacts"][1]["sha256"],
                hashlib.sha256(b"native-binary").hexdigest(),
            )

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


if __name__ == "__main__":
    unittest.main()
