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


SECTIONED = {
    "python-binding-native": {
        "totals": {"lines": 78.0, "branches": 68.0},
        "files": {"src/critical.rs": {"lines": 85.0, "branches": 75.0}},
    }
}


class SectionedFloorTests(unittest.TestCase):
    """A named section gates one lane without disturbing the root tables."""

    def test_a_section_enforces_its_own_totals_and_files(self) -> None:
        self.assertEqual(
            coverage.enforce(
                SECTIONED, report(ROOT), ROOT, section="python-binding-native"
            ),
            [],
        )

    def test_a_section_regression_names_the_section(self) -> None:
        failures = coverage.enforce(
            SECTIONED,
            report(ROOT, workspace=77.9),
            ROOT,
            section="python-binding-native",
        )
        self.assertTrue(
            any("python-binding-native totals lines" in failure for failure in failures),
            failures,
        )

    def test_an_absent_section_fails_closed(self) -> None:
        self.assertEqual(
            coverage.enforce(SECTIONED, report(ROOT), ROOT, section="no-such-lane"),
            ["coverage config has no [no-such-lane] table"],
        )

    def test_the_root_tables_are_untouched_by_a_section(self) -> None:
        # The workspace lane keeps reading [workspace]/[files] with no section.
        self.assertEqual(coverage.enforce(CONFIG, report(ROOT), ROOT), [])


def coverage_py_report(
    *, statements: tuple[int, int] = (93, 100), branches: tuple[int, int] = (7, 10)
) -> dict[str, object]:
    def summary(covered_lines: int, num_statements: int) -> dict[str, object]:
        return {
            "covered_lines": covered_lines,
            "num_statements": num_statements,
            "covered_branches": branches[0],
            "num_branches": branches[1],
        }

    return {
        "totals": summary(*statements),
        "files": {"src/module.py": {"summary": summary(*statements)}},
    }


COVERAGE_PY_CONFIG = {
    "python-binding-pure": {
        "totals": {"lines": 90.0, "branches": 60.0},
        "files": {"src/module.py": {"lines": 90.0, "branches": 60.0}},
    }
}


class CoveragePyFormatTests(unittest.TestCase):
    """coverage.py reports counters, not percentages, and blends the two."""

    def enforce(self, payload: dict[str, object]) -> list[str]:
        return coverage.enforce(
            COVERAGE_PY_CONFIG,
            payload,
            ROOT,
            section="python-binding-pure",
            report_format="coverage-py",
        )

    def test_counters_become_separate_line_and_branch_percentages(self) -> None:
        self.assertEqual(self.enforce(coverage_py_report()), [])

    def test_a_line_regression_is_derived_from_the_statement_counters(self) -> None:
        failures = self.enforce(coverage_py_report(statements=(80, 100)))
        self.assertTrue(any("lines: 80.00%" in failure for failure in failures), failures)

    def test_a_branch_regression_is_derived_from_the_branch_counters(self) -> None:
        failures = self.enforce(coverage_py_report(branches=(5, 10)))
        self.assertTrue(
            any("branches: 50.00%" in failure for failure in failures), failures
        )

    def test_a_file_with_no_branches_counts_as_fully_branch_covered(self) -> None:
        # 0/0 must be 100%, not 0%: an unbranching module has covered every
        # branch it has, and reporting 0% would make it impossible to gate.
        self.assertEqual(self.enforce(coverage_py_report(branches=(0, 0))), [])

    def test_a_missing_counter_fails_closed(self) -> None:
        payload = coverage_py_report()
        del payload["files"]["src/module.py"]["summary"]["num_branches"]  # type: ignore[index]
        failures = self.enforce(payload)
        self.assertTrue(
            any("branch counters" in failure for failure in failures), failures
        )


if __name__ == "__main__":
    unittest.main()
