from __future__ import annotations

import hashlib
import importlib.util
import json
import platform as platform_module
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run-consumer-harness.py"

JCS_SPEC = importlib.util.spec_from_file_location("jcs", ROOT / "scripts/jcs.py")
assert JCS_SPEC is not None and JCS_SPEC.loader is not None
jcs = importlib.util.module_from_spec(JCS_SPEC)
sys.modules[JCS_SPEC.name] = jcs
JCS_SPEC.loader.exec_module(jcs)

HARNESS_SPEC = importlib.util.spec_from_file_location("consumer_harness", SCRIPT)
assert HARNESS_SPEC is not None and HARNESS_SPEC.loader is not None
consumer_harness = importlib.util.module_from_spec(HARNESS_SPEC)
sys.modules[HARNESS_SPEC.name] = consumer_harness
HARNESS_SPEC.loader.exec_module(consumer_harness)

_HOST_OS = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}[platform_module.system()]
_HOST_CPU = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(
    platform_module.machine().lower(), platform_module.machine().lower()
)
_HOST_CLI_TARGET = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x64"): "x86_64-apple-darwin",
    ("linux", "x64"): "x86_64-unknown-linux-gnu",
    ("win32", "x64"): "x86_64-pc-windows-msvc",
}.get((_HOST_OS, _HOST_CPU))


def make_cli_binary(path: Path, *, version: str) -> None:
    """A POSIX shell-script stand-in for a real CLI binary: prints `version`
    when invoked with `--version`, matching what the real CLI's `--version`
    flag does."""
    path.write_text(f'#!/bin/sh\necho "{version}"\n', encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def make_pure_python_wheel(path: Path, *, name: str, version: str, platform_tag: str) -> None:
    """A minimal, real, pip-installable wheel -- valid `dist-info` metadata
    and a `RECORD` file (pip's install step fails without one), a trivial
    package body, zipped up by hand rather than built via a packaging tool,
    so this test has no build-tool dependency."""
    normalized = name.replace("-", "_")
    with tempfile.TemporaryDirectory() as staging:
        staging_path = Path(staging)
        package_dir = staging_path / normalized
        package_dir.mkdir()
        (package_dir / "__init__.py").write_text(
            f'def version():\n    return "{version}"\n', encoding="utf-8"
        )
        dist_info = staging_path / f"{normalized}-{version}.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
        )
        (dist_info / "WHEEL").write_text(
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
            f"Tag: py3-none-{platform_tag}\n",
            encoding="utf-8",
        )
        (dist_info / "RECORD").write_text("", encoding="utf-8")

        with zipfile.ZipFile(path, "w") as archive:
            for file_path in staging_path.rglob("*"):
                if file_path.is_file():
                    archive.write(file_path, file_path.relative_to(staging_path))


def write_manifest(
    path: Path,
    artifacts_root: Path,
    artifact_paths: list[Path],
    *,
    manifest_digest: str | None = None,
    compute_real_digest: bool = True,
) -> None:
    """`manifest_digest` sets an exact (possibly deliberately wrong) value;
    by default the helper computes the value every consumer-harness mode now
    verifies. An explicit digest overrides that default for negative tests."""
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
    release: dict[str, object] = {"version": "0.5.9"}
    if manifest_digest is not None:
        release["manifest_digest"] = manifest_digest
    elif compute_real_digest:
        release["manifest_digest"] = jcs.digest({"release": release, "artifacts": records})
    path.write_text(
        json.dumps({"schema_version": 4, "release": release, "artifacts": records}),
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
    def test_crate_dispatch_runs_the_packaged_consumer(self) -> None:
        archive = Path("/tmp/rookie-cookies-1.0.0.crate")
        with mock.patch.object(consumer_harness.subprocess, "run") as run:
            outcome = consumer_harness.exercise(
                {},
                archive,
                Path("/tmp/scratch"),
                contract=consumer_harness.platform_contract.load_contract(),
            )

        self.assertIn("isolated packaged-crate consumer", outcome)
        arguments = run.call_args.args[0]
        self.assertIn("check-packaged-rust-consumer.py", arguments[1])
        self.assertEqual(arguments[-2:], ["--archive", str(archive)])

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

    def test_reports_checksum_only_for_a_foreign_target_cli_binary(self) -> None:
        foreign_target = next(
            target
            for (_, target) in [
                (("darwin", "arm64"), "aarch64-apple-darwin"),
                (("darwin", "x64"), "x86_64-apple-darwin"),
                (("linux", "x64"), "x86_64-unknown-linux-gnu"),
                (("win32", "x64"), "x86_64-pc-windows-msvc"),
            ]
            if target != _HOST_CLI_TARGET
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / f"rookie-cookies-cli-{foreign_target}"
            make_cli_binary(binary, version="rookie-cookies 9.9.9")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [binary])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checksum-verified only", result.stdout)

    @unittest.skipIf(_HOST_CLI_TARGET is None, "host platform has no known CLI target triple")
    @unittest.skipIf(
        sys.platform == "win32",
        "make_cli_binary's #!/bin/sh stand-in isn't directly executable on Windows",
    )
    def test_cli_binary_matching_the_host_is_executed_outside_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / f"rookie-cookies-cli-{_HOST_CLI_TARGET}"
            make_cli_binary(binary, version="rookie-cookies 9.9.9")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [binary])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("executed outside the checkout", result.stdout)
            self.assertIn("rookie-cookies 9.9.9", result.stdout)

    def test_reports_checksum_only_for_a_foreign_platform_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            foreign_tag = "win_amd64" if _HOST_OS != "win32" else "manylinux_2_17_x86_64"
            wheel = root / f"rookie_cookies-9.9.9-py3-none-{foreign_tag}.whl"
            make_pure_python_wheel(
                wheel, name="rookie-cookies", version="9.9.9", platform_tag=foreign_tag
            )
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [wheel])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("checksum-verified only", result.stdout)

    def test_wheel_matching_the_host_is_installed_and_imported_outside_the_checkout(self) -> None:
        # PEP 600/425 arch tokens, not Rust/generic ones: manylinux says
        # "aarch64" where macOS says "arm64" for the same architecture (see
        # scripts/platform_contract.py's _WHEEL_CPU_TAGS for the same split).
        host_arch_tokens = {
            ("darwin", "arm64"): "arm64",
            ("darwin", "x64"): "x86_64",
            ("linux", "arm64"): "aarch64",
            ("linux", "x64"): "x86_64",
            ("win32", "x64"): "amd64",
        }
        host_platform_tag_prefixes = {
            "darwin": "macosx_11_0",
            "linux": "manylinux_2_17",
            "win32": "win",
        }
        if (_HOST_OS, _HOST_CPU) not in host_arch_tokens:
            self.skipTest(f"no known wheel arch token for {_HOST_OS}/{_HOST_CPU}")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tag = f"{host_platform_tag_prefixes[_HOST_OS]}_{host_arch_tokens[(_HOST_OS, _HOST_CPU)]}"
            wheel = root / f"rookie_cookies-9.9.9-py3-none-{tag}.whl"
            make_pure_python_wheel(
                wheel, name="rookie-cookies", version="9.9.9", platform_tag=tag
            )
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [wheel])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("installed into an isolated venv outside the checkout", result.stdout)
            self.assertIn("9.9.9", result.stdout)

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

    def test_fails_closed_when_manifest_helper_roles_no_longer_match_the_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-linux-x64-gnu-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies-linux-x64-gnu", os_tags=["linux"], cpu_tags=["x64"])
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            # The real contract's linux-x64-gnu npm-native cell is
            # ["keyring"] -- assert a manifest claiming something else is
            # caught, not trusted.
            manifest["artifacts"][0]["helper_roles"] = ["appbound"]
            manifest["release"]["manifest_digest"] = jcs.digest(
                {
                    "release": {
                        key: value
                        for key, value in manifest["release"].items()
                        if key != "manifest_digest"
                    },
                    "artifacts": manifest["artifacts"],
                }
            )
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = self.run_harness(root, manifest_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no longer matches the current platform contract", result.stderr)

    def test_check_native_coverage_passes_for_the_real_contract(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check-native-coverage"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_check_native_coverage_fails_for_an_uncovered_native_artifact_id(self) -> None:
        contract = json.loads((ROOT / "release" / "platform-contract.json").read_text(encoding="utf-8"))
        contract["cells"].append(
            {
                "artifact_id": "made-up-artifact-type",
                "registry": "npm",
                "os": None,
                "cpu": None,
                "libc": None,
                "features": [],
                "runtime_floor": {},
                "build": True,
                "advertise": True,
                "publish": True,
                "execute": "native",
                "helper_roles": [],
                "accepted_risk": None,
                "notes": None,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            contract_path = Path(temporary) / "platform-contract.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--check-native-coverage",
                    "--platform-contract",
                    str(contract_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("made-up-artifact-type", result.stderr)
            self.assertIn("has no exercise() routine", result.stderr)

    def test_output_writes_evidence_bound_to_the_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball], compute_real_digest=True)
            manifest_digest = json.loads(manifest_path.read_text(encoding="utf-8"))["release"]["manifest_digest"]
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["manifest_digest"], manifest_digest)
            self.assertEqual(evidence["schema_version"], 1)
            self.assertIn("os", evidence["host"])
            self.assertIn("cpu", evidence["host"])
            self.assertIn("generated_at", evidence)
            self.assertEqual(len(evidence["results"]), 1)
            self.assertEqual(evidence["results"][0]["path"], tarball.name)
            self.assertIn("structurally verified", evidence["results"][0]["outcome"])

    def test_output_fails_closed_without_a_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            # No manifest_digest= given -- write_manifest() omits the field.
            write_manifest(manifest_path, root, [tarball], compute_real_digest=False)
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest_digest", result.stderr)
            self.assertFalse(evidence_path.exists())

    def test_output_fails_closed_on_a_digest_that_does_not_match_the_manifest_content(self) -> None:
        # Regression test: manifest_digest was previously write-only --
        # copied verbatim into evidence without ever being checked against
        # the document it claims to bind. A syntactically valid but stale
        # (or hand-edited, or merge-corrupted) digest must be rejected, not
        # silently written into "evidence."
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            # A well-formed 64-hex digest that is not the real digest of
            # this manifest's actual release/artifacts content.
            write_manifest(manifest_path, root, [tarball], manifest_digest="d" * 64)
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)
            self.assertFalse(evidence_path.exists())

    def test_verification_without_output_rejects_a_stale_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball], manifest_digest="d" * 64)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)

    def test_output_fails_closed_on_an_empty_string_manifest_digest(self) -> None:
        # Regression test: `manifest_digest is None` alone does not catch a
        # present-but-falsy value like "" -- only checking for `None` would
        # let a manifest claim an empty binding and still write "evidence."
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball], manifest_digest="")
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest_digest", result.stderr)
            self.assertFalse(evidence_path.exists())

    def test_output_fails_closed_on_a_malformed_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball], manifest_digest="not-a-real-digest")
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest_digest", result.stderr)
            self.assertFalse(evidence_path.exists())

    def test_output_writes_no_partial_evidence_when_the_exercise_loop_fails(self) -> None:
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
            write_manifest(manifest_path, root, [tarball], compute_real_digest=True)
            evidence_path = root / "evidence.json"

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--manifest",
                    str(manifest_path),
                    "--artifacts-root",
                    str(root),
                    "--output",
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not exist in the tarball", result.stderr)
            self.assertFalse(evidence_path.exists(), "no partial evidence should survive a failed exercise loop")

    def test_without_output_flag_no_evidence_file_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tarball = root / "rookie-cookies-1.0.0.tgz"
            make_npm_tarball(tarball, name="rookie-cookies")
            manifest_path = root / "manifest.json"
            write_manifest(manifest_path, root, [tarball])

            result = self.run_harness(root, manifest_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(root.glob("evidence*.json")), [])


if __name__ == "__main__":
    unittest.main()
