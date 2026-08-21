from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_coverage", ROOT / "scripts/check-coverage.py"
)
assert SPEC and SPEC.loader
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def metric(percent: float) -> dict[str, float]:
    return {"percent": percent}


def report(root: Path, *, workspace: float = 80.0, critical: float = 90.0) -> dict[str, object]:
    return {
        "data": [
            {
                "totals": {"lines": metric(workspace), "branches": metric(workspace)},
                "files": [
                    {
                        "filename": str(root / "src/critical.rs"),
                        "summary": {
                            "lines": metric(critical),
                            "branches": metric(critical),
                        },
                    }
                ],
            }
        ]
    }


CONFIG = {
    "workspace": {"lines": 80.0, "branches": 70.0},
    "files": {"src/critical.rs": {"lines": 85.0, "branches": 75.0}},
}


class CoverageRatchetTests(unittest.TestCase):
    def test_passing_workspace_and_file_floors(self) -> None:
        self.assertEqual(coverage.enforce(CONFIG, report(ROOT), ROOT), [])

    def test_workspace_regression_fails(self) -> None:
        failures = coverage.enforce(CONFIG, report(ROOT, workspace=69.9), ROOT)
        self.assertTrue(any("workspace lines" in failure for failure in failures))
        self.assertTrue(any("workspace branches" in failure for failure in failures))

    def test_critical_file_regression_fails(self) -> None:
        failures = coverage.enforce(CONFIG, report(ROOT, critical=74.9), ROOT)
        self.assertTrue(any("src/critical.rs lines" in failure for failure in failures))
        self.assertTrue(any("src/critical.rs branches" in failure for failure in failures))

    def test_missing_critical_file_fails_closed(self) -> None:
        payload = report(ROOT)
        payload["data"][0]["files"] = []  # type: ignore[index]
        self.assertEqual(
            coverage.enforce(CONFIG, payload, ROOT),
            ["critical file missing from coverage report: src/critical.rs"],
        )


if __name__ == "__main__":
    unittest.main()
