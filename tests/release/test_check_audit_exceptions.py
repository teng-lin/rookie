from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-audit-exceptions.py"


def run(exceptions: str, report: dict[str, object], today: str = "2026-01-01") -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        exceptions_path = Path(temporary) / "audit-exceptions.toml"
        exceptions_path.write_text(exceptions, encoding="utf-8")
        report_path = Path(temporary) / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--exceptions",
                str(exceptions_path),
                "--report",
                str(report_path),
                "--today",
                today,
            ],
            capture_output=True,
            text=True,
        )


def audit_report(*advisory_ids: str) -> dict[str, object]:
    return {
        "vulnerabilities": {
            "list": [{"advisory": {"id": advisory_id}} for advisory_id in advisory_ids]
        }
    }


class AuditExceptionsTests(unittest.TestCase):
    def test_no_advisories_passes_with_empty_exceptions(self) -> None:
        result = run("", audit_report())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uncovered_advisory_fails(self) -> None:
        result = run("", audit_report("RUSTSEC-2024-0001"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RUSTSEC-2024-0001", result.stderr)

    def test_valid_unexpired_exception_covers_advisory(self) -> None:
        exceptions = """
[[exception]]
id = "RUSTSEC-2024-0001"
owner = "@alice"
rationale = "upstream fix pending, tracked in #999"
expires = "2026-06-01"
"""
        result = run(exceptions, audit_report("RUSTSEC-2024-0001"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_expired_exception_fails_even_if_advisory_present(self) -> None:
        exceptions = """
[[exception]]
id = "RUSTSEC-2024-0001"
owner = "@alice"
rationale = "upstream fix pending"
expires = "2025-01-01"
"""
        result = run(exceptions, audit_report("RUSTSEC-2024-0001"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expired", result.stderr)

    def test_exception_missing_owner_fails(self) -> None:
        exceptions = """
[[exception]]
id = "RUSTSEC-2024-0001"
rationale = "upstream fix pending"
expires = "2026-06-01"
"""
        result = run(exceptions, audit_report("RUSTSEC-2024-0001"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner is required", result.stderr)

    def test_malformed_advisory_id_fails(self) -> None:
        exceptions = """
[[exception]]
id = "not-an-advisory-id"
owner = "@alice"
rationale = "upstream fix pending"
expires = "2026-06-01"
"""
        result = run(exceptions, audit_report())
        self.assertNotEqual(result.returncode, 0)

    def test_duplicate_exception_id_fails(self) -> None:
        exceptions = """
[[exception]]
id = "RUSTSEC-2024-0001"
owner = "@alice"
rationale = "first"
expires = "2026-06-01"

[[exception]]
id = "RUSTSEC-2024-0001"
owner = "@bob"
rationale = "second"
expires = "2026-06-01"
"""
        result = run(exceptions, audit_report("RUSTSEC-2024-0001"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate", result.stderr)

    def test_unused_exception_does_not_fail_but_is_noted(self) -> None:
        exceptions = """
[[exception]]
id = "RUSTSEC-2024-0001"
owner = "@alice"
rationale = "upstream fix pending"
expires = "2026-06-01"
"""
        result = run(exceptions, audit_report())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no longer matches", result.stderr)


if __name__ == "__main__":
    unittest.main()
