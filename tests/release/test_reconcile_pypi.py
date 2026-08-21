from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "reconcile_pypi", REPOSITORY_ROOT / "scripts/reconcile-pypi.py"
)
assert SPEC is not None and SPEC.loader is not None
reconcile_pypi = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconcile_pypi
SPEC.loader.exec_module(reconcile_pypi)

VERSION = "1.2.3"
WHEEL = "rookie_cookies-1.2.3-cp311-abi3-manylinux_2_17_x86_64.whl"
SDIST = "rookie_cookies-1.2.3.tar.gz"


class ReconcilePyPITests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "dist").mkdir()
        self.manifest = self.root / "release-scan-manifest.json"

    def write_bundle(
        self,
        files: dict[str, bytes] | None = None,
        *,
        version: str = VERSION,
        kind: str = "release",
    ) -> dict[str, reconcile_pypi.Distribution]:
        files = files or {WHEEL: b"wheel bytes", SDIST: b"sdist bytes"}
        records: list[dict[str, object]] = []
        expected: dict[str, reconcile_pypi.Distribution] = {}
        for filename, contents in files.items():
            path = self.root / "dist" / filename
            path.write_bytes(contents)
            digest = hashlib.sha256(contents).hexdigest()
            records.append(
                {
                    "path": f"dist/{filename}",
                    "bytes": len(contents),
                    "sha256": digest,
                }
            )
            expected[filename] = reconcile_pypi.Distribution(
                filename=filename,
                path=path,
                sha256=digest,
                size=len(contents),
            )
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 4,
                    "release": {
                        "kind": kind,
                        "version": version,
                        "tag": f"v{version}",
                    },
                    "artifacts": records,
                }
            ),
            encoding="utf-8",
        )
        return expected

    def test_identical_files_are_accepted_and_only_missing_files_are_staged(
        self,
    ) -> None:
        expected = self.write_bundle()
        published = {WHEEL: expected[WHEEL].sha256}

        identical, missing = reconcile_pypi.reconcile(expected, published)
        output = self.root / "upload"
        reconcile_pypi.stage_missing(missing, output)

        self.assertEqual([item.filename for item in identical], [WHEEL])
        self.assertEqual([item.filename for item in missing], [SDIST])
        self.assertEqual([path.name for path in output.iterdir()], [SDIST])
        self.assertEqual((output / SDIST).read_bytes(), b"sdist bytes")

    def test_registry_digest_mismatch_fails_closed(self) -> None:
        expected = self.write_bundle()
        with self.assertRaisesRegex(reconcile_pypi.ReconcileError, "digest mismatch"):
            reconcile_pypi.reconcile(expected, {WHEEL: "f" * 64})

    def test_unexpected_registry_file_fails_closed(self) -> None:
        expected = self.write_bundle()
        with self.assertRaisesRegex(
            reconcile_pypi.ReconcileError, "outside the original"
        ):
            reconcile_pypi.reconcile(expected, {"injected.whl": "a" * 64})

    def test_manifest_must_be_for_the_requested_release(self) -> None:
        self.write_bundle(version="9.9.9")
        with self.assertRaisesRegex(reconcile_pypi.ReconcileError, "release.version"):
            reconcile_pypi.load_expected_distributions(
                self.manifest, self.root, VERSION
            )

    def test_candidate_manifest_is_never_publishable(self) -> None:
        self.write_bundle(kind="candidate")
        with self.assertRaisesRegex(reconcile_pypi.ReconcileError, "release.kind"):
            reconcile_pypi.load_expected_distributions(
                self.manifest, self.root, VERSION
            )

    def test_local_artifact_must_match_the_manifest(self) -> None:
        self.write_bundle()
        (self.root / "dist" / WHEEL).write_bytes(b"changed")
        with self.assertRaisesRegex(reconcile_pypi.ReconcileError, "SHA-256 mismatch"):
            reconcile_pypi.load_expected_distributions(
                self.manifest, self.root, VERSION
            )

    def test_cli_stages_absent_files_from_a_404_shaped_response(self) -> None:
        self.write_bundle()
        output = self.root / "upload"
        with mock.patch.object(
            reconcile_pypi, "fetch_pypi_release", return_value={"urls": []}
        ):
            result = reconcile_pypi.main(
                [
                    "--project",
                    "rookie-cookies",
                    "--version",
                    VERSION,
                    "--manifest",
                    str(self.manifest),
                    "--artifacts-root",
                    str(self.root),
                    "--output-dir",
                    str(output),
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual({path.name for path in output.iterdir()}, {WHEEL, SDIST})

    def test_require_complete_rejects_missing_files(self) -> None:
        self.write_bundle()
        with mock.patch.object(
            reconcile_pypi, "fetch_pypi_release", return_value={"urls": []}
        ):
            result = reconcile_pypi.main(
                [
                    "--project",
                    "rookie-cookies",
                    "--version",
                    VERSION,
                    "--manifest",
                    str(self.manifest),
                    "--artifacts-root",
                    str(self.root),
                    "--require-complete",
                ]
            )
        self.assertEqual(result, 1)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_crates_io_uses_oidc_without_a_stored_registry_token(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-crate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("id-token: write", workflow)
        self.assertIn(
            "rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18",
            workflow,
        )
        self.assertIn("steps.crates-io-auth.outputs.token", workflow)
        self.assertNotIn("secrets.CARGO_REGISTRY_TOKEN", workflow)

    def test_pypi_recovery_reuses_original_artifacts_and_publishes_only_missing_files(
        self,
    ) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-py.yml").read_text(
            encoding="utf-8"
        )
        recovery = workflow[workflow.index("  recovery:") :]
        self.assertIn("run-id: ${{ inputs.recovery_run_id }}", recovery)
        self.assertIn("--output-dir pypi-upload", recovery)
        self.assertIn("packages-dir: pypi-upload/", recovery)
        self.assertIn("--require-complete", recovery)
        self.assertLess(
            recovery.index("scripts/write-ci-proof.py"),
            recovery.index(
                "Publish only missing distributions with trusted publishing"
            ),
        )


if __name__ == "__main__":
    unittest.main()
