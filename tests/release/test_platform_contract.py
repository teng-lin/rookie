from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "platform_contract", REPOSITORY_ROOT / "scripts/platform_contract.py"
)
assert SPEC is not None and SPEC.loader is not None
platform_contract = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = platform_contract
SPEC.loader.exec_module(platform_contract)


def base_cell(**overrides: object) -> dict[str, object]:
    cell = {
        "artifact_id": "cli",
        "registry": "github-release",
        "os": "linux",
        "cpu": "x64",
        "libc": "gnu",
        "features": [],
        "runtime_floor": {},
        "build": True,
        "advertise": True,
        "publish": True,
        "execute": "native",
        "helper_roles": [],
        "accepted_risk": None,
        "notes": None,
        "target_triple": "x86_64-unknown-linux-gnu",
        "runner": "ubuntu-22.04",
    }
    cell.update(overrides)
    return cell


class RealContractTests(unittest.TestCase):
    def test_the_real_committed_contract_is_valid(self) -> None:
        contract = platform_contract.load_contract()
        self.assertEqual(platform_contract.validate(contract, today=date(2026, 1, 1)), [])

    def test_npm_native_packages_matches_the_original_hardcoded_order(self) -> None:
        contract = platform_contract.load_contract()
        self.assertEqual(
            platform_contract.npm_native_packages(contract),
            (
                "rookie-cookies-darwin-arm64",
                "rookie-cookies-darwin-x64",
                "rookie-cookies-linux-arm64-gnu",
                "rookie-cookies-linux-x64-gnu",
                "rookie-cookies-win32-x64-msvc",
            ),
        )

    def test_npm_publish_order_and_tarballs_come_from_publish_cells(self) -> None:
        contract = platform_contract.load_contract()
        packages = platform_contract.npm_publish_packages(contract)
        self.assertEqual(
            packages,
            (
                "rookie-cookies-darwin-arm64",
                "rookie-cookies-darwin-x64",
                "rookie-cookies-linux-arm64-gnu",
                "rookie-cookies-linux-x64-gnu",
                "rookie-cookies-win32-x64-msvc",
                "rookie-cookies",
            ),
        )
        self.assertEqual(packages[-1], "rookie-cookies")
        self.assertEqual(
            platform_contract.npm_publish_tarballs(contract, "1.2.3"),
            tuple(f"{package}-1.2.3.tgz" for package in packages),
        )

    def test_real_npm_manifests_and_optional_dependencies_match_contract(self) -> None:
        contract = platform_contract.load_contract()
        self.assertEqual(platform_contract.validate_npm_repository(contract), [])

    def test_windows_artifacts_record_the_internet_explorer_capability(self) -> None:
        contract = platform_contract.load_contract()
        windows_cells = [
            cell
            for cell in platform_contract.cells(contract)
            if cell.get("os") == "win32"
        ]
        self.assertGreaterEqual(len(windows_cells), 3)
        for cell in windows_cells:
            self.assertIn(
                "internet-explorer",
                cell["features"],
                f"{cell['artifact_id']} must record its shipped IE capability",
            )

        crate = platform_contract.cells(contract, artifact_id="crate")
        self.assertEqual(len(crate), 1)
        self.assertIn("internet-explorer", crate[0]["features"])

    def test_macos_x64_release_cells_use_the_intel_runner(self) -> None:
        contract = platform_contract.load_contract()
        matches = [
            cell
            for cell in platform_contract.cells(contract)
            if cell.get("os") == "darwin" and cell.get("cpu") in {"x64", "x86_64"}
        ]
        self.assertEqual({cell["artifact_id"] for cell in matches}, {"cli", "npm-native", "wheel"})
        self.assertTrue(matches)
        for cell in matches:
            self.assertEqual(cell.get("runner"), "macos-15-intel", cell)

    def test_darwin_wheel_matrix_uses_contract_runners(self) -> None:
        contract = platform_contract.load_contract()
        self.assertEqual(
            platform_contract.emit_matrix(contract, "wheel-darwin"),
            {
                "include": [
                    {"target": "aarch64", "runner": "macos-latest"},
                    {"target": "x86_64", "runner": "macos-15-intel"},
                ]
            },
        )

    def test_publish_cli_smokes_the_manifest_verified_binary_before_upload(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-cli.yml").read_text(
            encoding="utf-8"
        )
        rename = workflow.index("- name: Rename Windows")
        harness = workflow.index("- name: Run consumer harness against manifest-verified artifact")
        upload = workflow.index("- name: Upload Windows")
        self.assertLess(rename, harness)
        self.assertLess(harness, upload)

    def test_publish_cli_matrix_cells_execute_exact_artifacts_natively(self) -> None:
        contract = platform_contract.load_contract()
        matrix_targets = {
            entry["target"]
            for entry in platform_contract.emit_matrix(contract, "cli")["include"]
        }
        cli_cells = {
            cell["target_triple"]: cell
            for cell in platform_contract.cells(contract, artifact_id="cli")
        }
        self.assertEqual(set(cli_cells), matrix_targets)
        for target in sorted(matrix_targets):
            cell = cli_cells[target]
            self.assertEqual(cell.get("execute"), "native", cell)
            self.assertIsNone(cell.get("accepted_risk"), cell)

    def test_publish_npm_tests_the_downloaded_intel_addon(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-npm.yml").read_text(
            encoding="utf-8"
        )
        test_job = workflow[workflow.index("  test-macOS-windows-binding:") :]
        self.assertIn("host: macos-15-intel\n            target: x86_64-apple-darwin", test_job)
        self.assertLess(test_job.index("- name: Download artifacts"), test_job.index("- name: Test bindings"))

    def test_publish_py_uses_contract_runner_and_smokes_before_upload(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-py.yml").read_text(
            encoding="utf-8"
        )
        macos_job = workflow[workflow.index("  macos:") : workflow.index("  sdist:")]
        self.assertIn("runs-on: ${{ matrix.runner }}", macos_job)
        self.assertLess(macos_job.index("- name: Smoke-test the exact wheel"), macos_job.index("- name: Upload wheel"))

    def test_npm_workflow_consumes_contract_publish_inputs_and_order(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-npm.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(workflow.count("--emit-npm-tarballs"), 2)
        self.assertIn("--emit-npm-publish-order", workflow)
        self.assertNotIn("native_packages=(", workflow)
        self.assertNotIn('test "${#tarballs[@]}" -eq 5', workflow)

    def test_npm_first_package_bootstrap_is_explicit_and_contract_guarded(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github/workflows/publish-npm.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("bootstrap_package:", workflow)
        self.assertIn("if: inputs.bootstrap_package != ''", workflow)
        self.assertIn("NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}", workflow)
        self.assertIn("--emit-npm-publish-order", workflow)
        self.assertIn("could not prove that $BOOTSTRAP_PACKAGE is absent", workflow)
        self.assertIn('NPM_CONFIG_USERCONFIG="$bootstrap_npmrc" npm publish', workflow)

    def test_pack_script_outputs_exactly_the_contract_tarballs(self) -> None:
        contract = platform_contract.load_contract()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            node_root = root / "node"
            npm_root = node_root / "npm"
            node_root.mkdir()
            shutil.copy2(
                REPOSITORY_ROOT / "bindings/node/package.json",
                node_root / "package.json",
            )
            for package in platform_contract.npm_publish_packages(contract)[:-1]:
                platform_name = package.removeprefix("rookie-cookies-")
                source = REPOSITORY_ROOT / "bindings/node/npm" / platform_name
                destination = npm_root / platform_name
                destination.mkdir(parents=True)
                shutil.copy2(source / "package.json", destination / "package.json")
                metadata = json.loads((destination / "package.json").read_text(encoding="utf-8"))
                (destination / metadata["main"]).write_bytes(b"test-addon")

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_npm = fake_bin / "npm"
            fake_npm.write_text(
                """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

package = Path(sys.argv[2])
output = Path(sys.argv[sys.argv.index("--pack-destination") + 1])
metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
filename = f"{metadata['name']}-{metadata['version']}.tgz"
(output / filename).write_bytes(b"test-tarball")
print(json.dumps([{"filename": filename}]))
""",
                encoding="utf-8",
            )
            fake_npm.chmod(0o755)
            output = root / "tarballs"
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "scripts/package-npm-tarballs.py"),
                    "--node-root",
                    str(node_root),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            version = json.loads((node_root / "package.json").read_text(encoding="utf-8"))["version"]
            self.assertEqual(
                {path.name for path in output.glob("*.tgz")},
                set(platform_contract.npm_publish_tarballs(contract, version)),
            )

    def test_wheel_linux_matrix_includes_native_arm64_runner(self) -> None:
        contract = platform_contract.load_contract()
        matrix = platform_contract.wheel_linux_matrix(contract)
        by_target = {entry["target"]: entry["runner"] for entry in matrix["include"]}
        self.assertEqual(set(by_target), {"x86_64", "aarch64"})
        self.assertEqual(by_target["aarch64"], "ubuntu-24.04-arm")
        self.assertTrue(all(entry.get("target") and entry.get("runner") for entry in matrix["include"]))


class MatchCellForArtifactTests(unittest.TestCase):
    """Filenames are taken verbatim from the real `write-release-scan-manifest.py`
    invocations in publish-cli.yml/publish-npm.yml/publish-py.yml, not guessed."""

    def setUp(self) -> None:
        self.contract = platform_contract.load_contract()

    def test_matches_npm_root_tarball(self) -> None:
        cell = platform_contract.match_cell_for_artifact(self.contract, "rookie-cookies-1.0.0.tgz")
        assert cell is not None
        self.assertEqual(cell["artifact_id"], "npm-root")

    def test_matches_npm_native_tarball_and_addon_to_the_same_cell(self) -> None:
        tarball_cell = platform_contract.match_cell_for_artifact(
            self.contract, "rookie-cookies-linux-x64-gnu-1.0.0.tgz"
        )
        addon_cell = platform_contract.match_cell_for_artifact(
            self.contract, "rookie_cookies.linux-x64-gnu.node"
        )
        assert tarball_cell is not None and addon_cell is not None
        self.assertEqual(tarball_cell, addon_cell)
        self.assertEqual(tarball_cell["helper_roles"], ["keyring"])

    def test_matches_cli_binary_with_and_without_exe_suffix(self) -> None:
        unix_cell = platform_contract.match_cell_for_artifact(
            self.contract, "rookie-cookies-cli-x86_64-unknown-linux-gnu"
        )
        windows_cell = platform_contract.match_cell_for_artifact(
            self.contract, "rookie-cookies-cli-x86_64-pc-windows-msvc.exe"
        )
        assert unix_cell is not None and windows_cell is not None
        self.assertEqual(unix_cell["helper_roles"], ["keyring"])
        self.assertEqual(sorted(windows_cell["helper_roles"]), ["appbound", "dpapi"])

    def test_matches_wheel_platform_tags_across_architectures(self) -> None:
        cases = {
            "rookie_cookies-1.0.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl": (
                "linux",
                "x86_64",
            ),
            "rookie_cookies-1.0.0-cp311-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl": (
                "linux",
                "aarch64",
            ),
            "rookie_cookies-1.0.0-cp311-abi3-win_amd64.whl": ("win32", "x64"),
            "rookie_cookies-1.0.0-cp311-abi3-macosx_11_0_arm64.whl": ("darwin", "aarch64"),
        }
        for filename, (os_name, cpu) in cases.items():
            with self.subTest(filename=filename):
                cell = platform_contract.match_cell_for_artifact(self.contract, filename)
                assert cell is not None
                self.assertEqual((cell["os"], cell["cpu"]), (os_name, cpu))

    def test_matches_sdist_by_extension_with_no_platform_info(self) -> None:
        cell = platform_contract.match_cell_for_artifact(self.contract, "rookie_cookies-1.0.0.tar.gz")
        assert cell is not None
        self.assertEqual(cell["artifact_id"], "sdist")

    def test_matches_packaged_rust_crate(self) -> None:
        cell = platform_contract.match_cell_for_artifact(
            self.contract, "rookie-cookies-1.0.0.crate"
        )
        assert cell is not None
        self.assertEqual(cell["artifact_id"], "crate")

    def test_unrecognized_wheel_platform_tag_raises_instead_of_guessing(self) -> None:
        with self.assertRaises(platform_contract.ArtifactMatchError):
            platform_contract.match_cell_for_artifact(
                self.contract, "rookie_cookies-1.0.0-cp311-abi3-freebsd_13_x86_64.whl"
            )

    def test_unrecognized_filename_shape_returns_none(self) -> None:
        self.assertIsNone(platform_contract.match_cell_for_artifact(self.contract, "README.md"))


class ValidationTests(unittest.TestCase):
    def test_rejects_duplicate_cells(self) -> None:
        contract = {"cells": [base_cell(), base_cell()]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("duplicate cell" in failure for failure in failures))

    def test_rejects_unknown_registry(self) -> None:
        contract = {"cells": [base_cell(registry="sourceforge")]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("registry" in failure for failure in failures))

    def test_rejects_unknown_execute_state(self) -> None:
        contract = {"cells": [base_cell(execute="probably")]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("execute" in failure for failure in failures))

    def test_rejects_unknown_helper_role(self) -> None:
        contract = {"cells": [base_cell(helper_roles=["magic"])]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("unknown helper_roles" in failure for failure in failures))

    def test_rejects_publish_without_advertise(self) -> None:
        contract = {"cells": [base_cell(advertise=False, publish=True)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("publish=true requires advertise=true" in failure for failure in failures))

    def test_rejects_advertise_without_build(self) -> None:
        contract = {"cells": [base_cell(build=False, advertise=True, publish=False)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("advertise=true requires build=true" in failure for failure in failures))

    def test_advertised_non_native_cell_requires_accepted_risk(self) -> None:
        contract = {"cells": [base_cell(execute="qemu", accepted_risk=None)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("requires accepted_risk" in failure for failure in failures))

    def test_accepted_risk_with_expired_date_fails(self) -> None:
        risk = {"owner": "a", "rationale": "b", "expires": "2020-01-01"}
        contract = {"cells": [base_cell(execute="qemu", accepted_risk=risk)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("expired" in failure for failure in failures))

    def test_accepted_risk_missing_owner_fails(self) -> None:
        risk = {"owner": "", "rationale": "b", "expires": "2030-01-01"}
        contract = {"cells": [base_cell(execute="qemu", accepted_risk=risk)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("accepted_risk.owner" in failure for failure in failures))

    def test_valid_accepted_risk_on_qemu_cell_passes(self) -> None:
        risk = {"owner": "a", "rationale": "b", "expires": "2030-01-01"}
        contract = {"cells": [base_cell(execute="qemu", accepted_risk=risk)]}
        self.assertEqual(platform_contract.validate(contract, today=date(2026, 1, 1)), [])

    def test_native_cell_with_unnecessary_accepted_risk_fails(self) -> None:
        risk = {"owner": "a", "rationale": "b", "expires": "2030-01-01"}
        contract = {"cells": [base_cell(execute="native", accepted_risk=risk)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("does not need one" in failure for failure in failures))

    def test_native_cell_without_accepted_risk_passes(self) -> None:
        contract = {"cells": [base_cell(execute="native", accepted_risk=None)]}
        self.assertEqual(platform_contract.validate(contract, today=date(2026, 1, 1)), [])

    def test_cli_cell_missing_target_triple_fails(self) -> None:
        contract = {"cells": [base_cell(target_triple=None)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("target_triple" in failure for failure in failures))

    def test_cli_cell_missing_runner_fails(self) -> None:
        contract = {"cells": [base_cell(runner=None)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("runner" in failure for failure in failures))

    def test_npm_native_cell_missing_npm_platform_fails(self) -> None:
        contract = {
            "cells": [
                base_cell(
                    artifact_id="npm-native",
                    registry="npm",
                    target_triple="x86_64-unknown-linux-gnu",
                    runner="ubuntu-latest",
                )
            ]
        }
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("npm_platform" in failure for failure in failures))

    def test_wheel_cell_missing_cpu_fails(self) -> None:
        contract = {"cells": [base_cell(artifact_id="wheel", registry="pypi", cpu=None)]}
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("cpu" in failure for failure in failures))

    def test_macos_wheel_cell_missing_runner_fails(self) -> None:
        contract = {
            "cells": [
                base_cell(
                    artifact_id="wheel",
                    registry="pypi",
                    os="darwin",
                    cpu="x86_64",
                    runner=None,
                )
            ]
        }
        failures = platform_contract.validate(contract, today=date(2026, 1, 1))
        self.assertTrue(any("macOS wheel" in failure and "runner" in failure for failure in failures))

    def test_artifact_types_without_extra_requirements_are_unaffected(self) -> None:
        contract = {"cells": [base_cell(artifact_id="crate", registry="crates.io", os=None, cpu=None, libc=None)]}
        self.assertEqual(platform_contract.validate(contract, today=date(2026, 1, 1)), [])


class DiffCellsTests(unittest.TestCase):
    def test_no_difference_reports_nothing(self) -> None:
        contract = {"cells": [base_cell(artifact_id="cli")]}
        self.assertEqual(platform_contract.diff_cells(contract, copy.deepcopy(contract)), [])

    def test_a_new_cell_in_head_is_reported(self) -> None:
        base = {"cells": [base_cell(artifact_id="cli")]}
        head = {"cells": [base_cell(artifact_id="cli"), base_cell(artifact_id="wheel")]}
        self.assertEqual(platform_contract.diff_cells(base, head), ["wheel"])

    def test_a_changed_cell_is_reported(self) -> None:
        base = {"cells": [base_cell(artifact_id="cli", os="linux")]}
        head = {"cells": [base_cell(artifact_id="cli", os="darwin")]}
        self.assertEqual(platform_contract.diff_cells(base, head), ["cli"])

    def test_a_cell_removed_in_head_is_not_reported(self) -> None:
        base = {"cells": [base_cell(artifact_id="cli"), base_cell(artifact_id="wheel")]}
        head = {"cells": [base_cell(artifact_id="cli")]}
        self.assertEqual(platform_contract.diff_cells(base, head), [])

    def test_results_are_sorted(self) -> None:
        base = {"cells": []}
        head = {
            "cells": [
                base_cell(artifact_id="wheel"),
                base_cell(artifact_id="cli"),
                base_cell(artifact_id="crate"),
            ]
        }
        self.assertEqual(platform_contract.diff_cells(base, head), ["cli", "crate", "wheel"])

    def test_a_changed_non_last_cell_sharing_an_artifact_id_is_still_reported(self) -> None:
        # Regression test: an artifact_id is not unique -- the real contract
        # has many cells per artifact_id (one per platform/libc). Keying
        # only on artifact_id (as an earlier version of this function did)
        # would silently collapse three "wheel" cells down to whichever one
        # happens to be last in list order, hiding a change to either of
        # the first two entirely.
        base = {
            "cells": [
                base_cell(artifact_id="wheel", os="linux", cpu="x64"),
                base_cell(artifact_id="wheel", os="darwin", cpu="arm64"),
                base_cell(artifact_id="wheel", os="win32", cpu="x64"),
            ]
        }
        head = copy.deepcopy(base)
        head["cells"][0]["build"] = False  # changes the *first* wheel cell, not the last
        self.assertEqual(platform_contract.diff_cells(base, head), ["wheel"])

    def test_a_new_cell_sharing_an_artifact_id_with_an_unchanged_sibling_is_reported(self) -> None:
        base = {"cells": [base_cell(artifact_id="wheel", os="linux", cpu="x64")]}
        head = {
            "cells": [
                base_cell(artifact_id="wheel", os="linux", cpu="x64"),
                base_cell(artifact_id="wheel", os="darwin", cpu="arm64"),
            ]
        }
        self.assertEqual(platform_contract.diff_cells(base, head), ["wheel"])

    def test_a_changed_cell_is_reported_only_once_even_if_a_sibling_also_shares_its_id(self) -> None:
        base = {
            "cells": [
                base_cell(artifact_id="wheel", os="linux", cpu="x64"),
                base_cell(artifact_id="wheel", os="darwin", cpu="arm64"),
            ]
        }
        head = copy.deepcopy(base)
        head["cells"][0]["build"] = False
        head["cells"][1]["build"] = False
        self.assertEqual(platform_contract.diff_cells(base, head), ["wheel"])


class RealContractDiffCellsTests(unittest.TestCase):
    """Regression coverage against the actual committed contract, not just
    synthetic fixtures -- this is exactly the shape of input that exposed
    the artifact_id-collision bug (several real `wheel` cells)."""

    def test_changing_a_non_last_real_wheel_cell_is_detected(self) -> None:
        contract = platform_contract.load_contract()
        wheel_cells = platform_contract.cells(contract, artifact_id="wheel")
        self.assertGreater(
            len(wheel_cells), 1, "this regression test needs more than one real wheel cell to be meaningful"
        )

        head = copy.deepcopy(contract)
        head_wheel_cells = platform_contract.cells(head, artifact_id="wheel")
        head_wheel_cells[0]["build"] = not head_wheel_cells[0]["build"]

        self.assertEqual(platform_contract.diff_cells(contract, head), ["wheel"])


class DiffCellsCliTests(unittest.TestCase):
    def _init_repo(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        (root / "release").mkdir()
        return root

    def _commit_contract(self, root: Path, contract: dict[str, object], message: str) -> str:
        (root / "release" / "platform-contract.json").write_text(
            json.dumps(contract), encoding="utf-8"
        )
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@example.com",
                "-c",
                "user.name=t",
                "commit",
                "--quiet",
                "--allow-empty",
                "-m",
                message,
            ],
            cwd=root,
            check=True,
        )
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
        ).stdout.strip()

    def test_diff_cells_prints_changed_artifact_ids_between_two_real_commits(self) -> None:
        root = self._init_repo()
        base_sha = self._commit_contract(
            root, {"cells": [base_cell(artifact_id="cli")]}, "base"
        )
        head_sha = self._commit_contract(
            root,
            {"cells": [base_cell(artifact_id="cli"), base_cell(artifact_id="wheel")]},
            "head",
        )

        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "platform_contract.py"),
                "--contract",
                str(root / "release" / "platform-contract.json"),
                "--diff-cells",
                base_sha,
                head_sha,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "wheel")

    def test_diff_cells_prints_nothing_and_exits_zero_when_nothing_changed(self) -> None:
        root = self._init_repo()
        contract = {"cells": [base_cell(artifact_id="cli")]}
        base_sha = self._commit_contract(root, contract, "base")
        head_sha = self._commit_contract(root, copy.deepcopy(contract), "head (no real change)")

        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "platform_contract.py"),
                "--contract",
                str(root / "release" / "platform-contract.json"),
                "--diff-cells",
                base_sha,
                head_sha,
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_diff_cells_fails_closed_on_an_unknown_ref(self) -> None:
        root = self._init_repo()
        head_sha = self._commit_contract(
            root, {"cells": [base_cell(artifact_id="cli")]}, "head"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "platform_contract.py"),
                "--contract",
                str(root / "release" / "platform-contract.json"),
                "--diff-cells",
                "0" * 40,
                head_sha,
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error:", result.stderr)

    def test_diff_cells_rejects_a_ref_that_looks_like_an_option(self) -> None:
        root = self._init_repo()
        head_sha = self._commit_contract(
            root, {"cells": [base_cell(artifact_id="cli")]}, "head"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY_ROOT / "scripts" / "platform_contract.py"),
                "--contract",
                str(root / "release" / "platform-contract.json"),
                "--diff-cells",
                "--not-a-real-ref",
                head_sha,
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("looks like an option", result.stderr)


if __name__ == "__main__":
    unittest.main()
