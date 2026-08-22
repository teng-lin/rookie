from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from run_active_writer_e2e import ActiveWriterError
from run_browser_cookie_stress_e2e import (
    require_ci_sandbox,
    surface_commands,
)
from run_exact_corpus_e2e import find_chromium_database
from run_partition_context_e2e import require_remote_sandbox


class IsolatedBrowserRunnerTests(unittest.TestCase):
    def test_partition_runner_refuses_non_ci_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ActiveWriterError, "isolated CI"):
                    require_remote_sandbox(Path(temporary) / "partition")

    def test_stress_runner_refuses_non_ci_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ActiveWriterError, "isolated CI"):
                    require_ci_sandbox(Path(temporary) / "stress")

    def test_depth_runners_reject_sandbox_outside_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as runner_temp:
            with tempfile.TemporaryDirectory() as outside:
                environment = {"CI": "true", "RUNNER_TEMP": runner_temp}
                with mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(
                        ActiveWriterError, "outside RUNNER_TEMP"
                    ):
                        require_remote_sandbox(Path(outside) / "partition")
                    with self.assertRaisesRegex(
                        ActiveWriterError, "outside RUNNER_TEMP"
                    ):
                        require_ci_sandbox(Path(outside) / "stress")

    def test_depth_runners_accept_only_runner_temp_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as runner_temp:
            environment = {"CI": "true", "RUNNER_TEMP": runner_temp}
            with mock.patch.dict(os.environ, environment, clear=True):
                partition = require_remote_sandbox(Path(runner_temp) / "partition")
                stress = require_ci_sandbox(Path(runner_temp) / "stress")
            self.assertTrue(partition.is_dir())
            self.assertTrue(stress.is_dir())

    def test_stress_runner_exercises_all_four_public_surfaces(self) -> None:
        commands = surface_commands(
            "chromium", Path("/tmp/disposable/Cookies"), Path("/venv/python")
        )
        self.assertEqual(
            [name for name, _ in commands], ["python", "node", "rust", "cli"]
        )
        self.assertTrue(all("detailed" in command for _, command in commands))

    def test_exact_runner_finds_only_a_supplied_profile_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary)
            database = profile / "Default/Network/Cookies"
            database.parent.mkdir(parents=True)
            database.touch()
            self.assertEqual(find_chromium_database(profile), database.resolve())


if __name__ == "__main__":
    unittest.main()
