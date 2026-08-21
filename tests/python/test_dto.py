"""Round-trip tests for the generated typed DTOs in rookie_cookies.dto.

These use hand-built dicts matching the wire shape rather than a real
extraction, so they do not depend on what is installed on the host -- see
test_report_api.py for that same convention.
"""

from __future__ import annotations

import dataclasses
import unittest
from unittest import mock

import rookie_cookies
from rookie_cookies import dto

_COOKIE = {
    "domain": ".example.test",
    "path": "/",
    "secure": True,
    "expires": 1_700_000_000,
    "name": "session",
    "value": "abc123",
    "http_only": True,
    "same_site": 1,
}

_PROFILE_IDENTITY = {
    "browser_id": "chrome",
    "installation_id": "a" * 64,
    "profile_id": "b" * 64,
    "display_name": "Default",
    "path": "display-only",
    "path_lossy": False,
}

_STATS = {
    "rows_seen": 1,
    "cookies_emitted": 1,
    "rows_skipped": 0,
    "rows_rejected": 0,
    "provider_failures": 0,
    "acquisition_attempts": 1,
    "counters_saturated": False,
}

_ISSUE = {
    "code": "decode_failed",
    "stage": "decode",
    "severity": "warning",
    "cause": "decode_failed",
    "provider": None,
    "tier": None,
    "retryability": "unknown",
    "occurrences": 1,
    "samples": [],
    "browser_id": "chrome",
    "installation_id": "a" * 64,
    "profile_id": "b" * 64,
    "message": "legacy diagnostic",
}

_REPORT = {
    "schema_version": 1,
    "status": "partial",
    "termination": "completed",
    "summary": {
        "registered_browsers": 1,
        "browsers_detected": 1,
        "browsers_not_detected": 0,
        "installations_discovered": 1,
        "profiles_discovered": 1,
        "sources_succeeded": 1,
        "sources_failed": 0,
        "rows_seen": 1,
        "cookies_emitted": 1,
        "rows_skipped": 0,
        "rows_rejected": 0,
        "provider_failures": 0,
        "counters_saturated": False,
    },
    "profiles": [
        {
            "profile": _PROFILE_IDENTITY,
            "sources": [
                {
                    "source": {
                        "role": "persistent",
                        "format": "chromium_sqlite",
                        "path": "display-only/Cookies",
                        "path_lossy": False,
                        "precedence": 10,
                    },
                    "status": "succeeded",
                    "selected": True,
                    "acquisition_strategy": "live_read_only",
                    "cookies": [_COOKIE],
                    "stats": _STATS,
                    "issues": [_ISSUE],
                }
            ],
            "stats": _STATS,
            "issues": [],
        }
    ],
    "issues": [],
}


class DtoRoundTripTest(unittest.TestCase):
    def test_cookie_round_trips(self) -> None:
        cookie = dto.Cookie.from_dict(_COOKIE)
        self.assertEqual(dataclasses.asdict(cookie), _COOKIE)

    def test_extraction_report_round_trips_through_nested_dataclasses(self) -> None:
        report = dto.ExtractionReport.from_dict(_REPORT)
        self.assertIsInstance(report, dto.ExtractionReport)
        self.assertIsInstance(report.profiles[0], dto.ProfileExtraction)
        self.assertIsInstance(report.profiles[0].sources[0], dto.SourceExtraction)
        self.assertIsInstance(report.profiles[0].sources[0].cookies[0], dto.Cookie)
        self.assertIsInstance(report.profiles[0].sources[0].issues[0], dto.ExtractionIssue)
        self.assertEqual(dataclasses.asdict(report), _REPORT)

    def test_missing_optional_fields_default_like_the_frozen_report_json_test(self) -> None:
        # Mirrors report_core.rs's
        # `frozen_pre_pr3_report_json_defaults_new_wire_fields` test: an older
        # wire payload missing newer optional fields still converts.
        minimal_report = dict(_REPORT)
        minimal_summary = dict(_REPORT["summary"])
        del minimal_summary["rows_rejected"]
        del minimal_summary["provider_failures"]
        minimal_report["summary"] = minimal_summary
        del minimal_report["schema_version"]
        del minimal_report["termination"]

        report = dto.ExtractionReport.from_dict(minimal_report)
        self.assertEqual(report.schema_version, 1)
        self.assertEqual(report.termination, "completed")
        self.assertEqual(report.summary.rows_rejected, 0)
        self.assertEqual(report.summary.provider_failures, 0)

    def test_all_dto_names_are_exported(self) -> None:
        for name in dto.__all__:
            self.assertTrue(hasattr(dto, name), name)
            self.assertTrue(dataclasses.is_dataclass(getattr(dto, name)), name)

    def test_dtos_are_frozen(self) -> None:
        # Pins scripts/generate-python-dto.py's `@dataclass(frozen=True)`
        # choice: these represent already-finalized report data.
        cookie = dto.Cookie.from_dict(_COOKIE)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cookie.value = "mutated"

    def test_report_dto_is_a_first_class_typed_view(self) -> None:
        with mock.patch.object(rookie_cookies, "report", return_value=_REPORT) as report:
            result = rookie_cookies.report_dto("chrome", select="legacy_first")

        self.assertIsInstance(result, dto.ExtractionReport)
        self.assertIsInstance(result.profiles[0], dto.ProfileExtraction)
        report.assert_called_once_with(
            "chrome",
            profile=None,
            domains=None,
            select="legacy_first",
            timeout=None,
            cancellation=None,
            app_bound="injection_only",
        )


if __name__ == "__main__":
    unittest.main()
