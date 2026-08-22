"""Concurrent stress-runner tests using only synthetic subprocess output."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


E2E = Path(__file__).parent
sys.path.insert(0, str(E2E))


def load_module(name: str, filename: str):
    path = E2E / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STRESS = load_module("run_cookie_stress", "run_cookie_stress.py")


COOKIE = {
    "domain": "seed.rookie-0.test",
    "path": "/",
    "secure": True,
    "expires": 4_102_444_800,
    "name": "stress_0_0",
    "value": "seed-0-0",
    "http_only": True,
    "same_site": 1,
}
MANIFEST = {
    "schema_version": 1,
    "tiers": ["stress"],
    "identities": {
        "filtered_flat": ["domain", "path", "name"],
        "unfiltered_flat": ["domain", "path", "name"],
        "detailed": ["cookie.domain", "cookie.path", "cookie.name"],
    },
    "expected": {
        "filtered_flat": [COOKIE],
        "unfiltered_flat": [COOKIE],
        "detailed": [
            {
                "cookie": COOKIE,
                "context": {
                    "top_frame_site_key": None,
                    "has_cross_site_ancestor": None,
                    "source_scheme": None,
                    "source_port": None,
                    "is_persistent": None,
                    "origin_attributes": "",
                    "user_context_id": None,
                    "partition_key": None,
                    "private_browsing_id": None,
                },
            }
        ],
    },
}


class CookieStressRunnerTests(unittest.TestCase):
    def completed(self, records: list[dict]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            ["synthetic"], 0, stdout=json.dumps(records), stderr=""
        )

    @mock.patch.object(STRESS.subprocess, "run")
    def test_every_concurrent_run_is_exactly_verified(self, run: mock.Mock) -> None:
        run.return_value = self.completed([COOKIE])
        result = STRESS.run_stress(
            ["synthetic"],
            timeout=1,
            manifest=MANIFEST,
            projection="filtered_flat",
            surface="python",
            workers=4,
            iterations=3,
        )
        self.assertEqual(len(run.call_args_list), 12)
        self.assertEqual(result["runs"], 12)
        self.assertEqual(result["rows_per_run"], 1)

    @mock.patch.object(STRESS.subprocess, "run")
    def test_one_excess_row_fails_the_stress_run(self, run: mock.Mock) -> None:
        excess = {**COOKIE, "name": "unexpected"}
        run.return_value = self.completed([COOKIE, excess])
        with self.assertRaisesRegex(STRESS.StressError, "excess identities"):
            STRESS.run_stress(
                ["synthetic"],
                timeout=1,
                manifest=MANIFEST,
                projection="filtered_flat",
                surface="cli",
                workers=2,
                iterations=1,
            )

    @mock.patch.object(STRESS.subprocess, "run")
    def test_nonzero_surface_fails_with_diagnostics(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            ["synthetic"], 9, stdout="", stderr="locked"
        )
        with self.assertRaisesRegex(STRESS.StressError, "exited 9: locked"):
            STRESS.run_once(
                ["synthetic"],
                timeout=1,
                manifest=MANIFEST,
                projection="filtered_flat",
                surface="rust",
                ordinal=0,
            )


if __name__ == "__main__":
    unittest.main()
