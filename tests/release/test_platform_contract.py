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


if __name__ == "__main__":
    unittest.main()
