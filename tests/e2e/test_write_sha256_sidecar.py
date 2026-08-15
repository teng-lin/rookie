import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "write-sha256-sidecar.py"


class WriteSha256SidecarTests(unittest.TestCase):
    def test_manifest_is_portable_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "rookie-cookies-cli-x86_64-pc-windows-msvc.exe"
            payload = b"portable release artifact\x00\xff"
            artifact.write_bytes(payload)

            completed = subprocess.run(
                [sys.executable, str(SCRIPT), artifact.name],
                cwd=temp_dir,
                check=True,
                capture_output=True,
                text=True,
            )

            sidecar = artifact.with_name(f"{artifact.name}.sha256")
            expected = f"{hashlib.sha256(payload).hexdigest()}  {artifact.name}\n".encode(
                "ascii"
            )
            self.assertEqual(sidecar.read_bytes(), expected)
            self.assertEqual(Path(completed.stdout.strip()), Path(f"{artifact.name}.sha256"))
            self.assertNotIn(b"\r", sidecar.read_bytes())

            verifiers = [
                (["sha256sum", "-c", sidecar.name], "sha256sum"),
                (["shasum", "-a", "256", "-c", sidecar.name], "shasum"),
            ]
            for command, executable in verifiers:
                if shutil.which(executable) is None:
                    continue
                with self.subTest(verifier=executable):
                    subprocess.run(command, cwd=temp_dir, check=True, capture_output=True)

    def test_missing_artifact_fails_without_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "missing.exe"],
                cwd=temp_dir,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("artifact is not a regular file", completed.stderr)
            self.assertFalse((Path(temp_dir) / "missing.exe.sha256").exists())


if __name__ == "__main__":
    unittest.main()
