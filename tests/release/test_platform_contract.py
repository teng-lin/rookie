from __future__ import annotations

import copy
import importlib.util
import sys
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
                "rookie-cookies-linux-x64-gnu",
                "rookie-cookies-win32-x64-msvc",
            ),
        )


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
            "rookie_cookies-1.0.0-cp311-abi3-manylinux_2_17_i686.manylinux2014_i686.whl": ("linux", "x86"),
            "rookie_cookies-1.0.0-cp311-abi3-manylinux_2_17_armv7l.whl": ("linux", "armv7"),
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

    def test_artifact_types_without_extra_requirements_are_unaffected(self) -> None:
        contract = {"cells": [base_cell(artifact_id="crate", registry="crates.io", os=None, cpu=None, libc=None)]}
        self.assertEqual(platform_contract.validate(contract, today=date(2026, 1, 1)), [])


if __name__ == "__main__":
    unittest.main()
