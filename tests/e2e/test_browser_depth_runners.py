from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
from zipfile import ZipFile

from run_active_writer_e2e import ActiveWriterError
from run_browser_cookie_stress_e2e import (
    locked_database_copy,
    require_ci_sandbox,
    surface_commands,
    validate_stress_profile_proof,
)
from run_exact_corpus_e2e import find_chromium_database, stage_discovered_profile
from run_partition_context_e2e import (
    FIREFOX_CONTAINER_EXTENSION_ID,
    require_remote_sandbox,
    stage_firefox_container_extension,
)


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

    def test_firefox_container_extension_is_staged_as_a_scoped_xpi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile"
            profile.mkdir()
            target = stage_firefox_container_extension(profile)
            self.assertEqual(
                target.name,
                f"{FIREFOX_CONTAINER_EXTENSION_ID}.xpi",
            )
            with ZipFile(target) as archive:
                self.assertEqual(
                    set(archive.namelist()), {"manifest.json", "background.js"}
                )

    def test_stress_runner_exercises_all_four_public_surfaces(self) -> None:
        commands = surface_commands(
            "chromium",
            Path("/tmp/disposable/Cookies"),
            Path("/venv/python"),
            "chrome",
        )
        self.assertEqual(
            [name for name, _ in commands], ["python", "node", "rust", "cli"]
        )
        self.assertTrue(all("detailed" in command for _, command in commands))
        self.assertTrue(
            all(
                "chrome" in command
                for surface, command in commands
                if surface != "cli" or "--browser-id" in command
            )
        )

    def test_stress_profile_proof_binds_live_pid_profile_database_and_churn(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile"
            profile.mkdir()
            database = profile / "cookies.sqlite"
            database.touch()
            manifest = Path(temporary) / "manifest.json"
            manifest.touch()
            payload = {
                "protocolVersion": 1,
                "sequence": 2,
                "phase": "mutated",
                "engine": "firefox",
                "seederPid": 20,
                "browserProcessIds": [21],
                "profileDir": str(profile.resolve()),
                "databasePath": str(database.resolve()),
                "manifest": str(manifest.resolve()),
                "liveness": {
                    "readyState": "complete",
                    "cookieCount": 320,
                    "writeChurn": {"active": True, "requests": 9},
                },
            }
            with mock.patch(
                "run_browser_cookie_stress_e2e.process_is_alive", return_value=True
            ):
                validate_stress_profile_proof(
                    payload,
                    engine="firefox",
                    sequence=2,
                    phase="mutated",
                    profile=profile,
                    database=database,
                    churn_active=True,
                    manifest=manifest,
                )
            payload["browserProcessIds"] = []
            with self.assertRaisesRegex(ActiveWriterError, "browser PIDs"):
                validate_stress_profile_proof(
                    payload,
                    engine="firefox",
                    sequence=2,
                    phase="mutated",
                    profile=profile,
                    database=database,
                    churn_active=True,
                    manifest=manifest,
                )

    def test_locked_database_copy_is_rollback_locked_and_recoverable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.sqlite"
            connection = sqlite3.connect(source)
            connection.execute("create table cookies (name text)")
            connection.execute("insert into cookies values ('stable')")
            connection.commit()
            connection.close()
            target = Path(temporary) / "locked.sqlite"
            lock = locked_database_copy(source, target)
            reader = sqlite3.connect(target, timeout=0)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    reader.execute("select * from cookies").fetchall()
            finally:
                reader.close()
                lock.execute("rollback")
                lock.close()
            recovered = sqlite3.connect(target)
            try:
                self.assertEqual(
                    recovered.execute("select name from cookies").fetchall(),
                    [("stable",)],
                )
            finally:
                recovered.close()

    def test_exact_runner_finds_only_a_supplied_profile_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary)
            database = profile / "Default/Network/Cookies"
            database.parent.mkdir(parents=True)
            database.touch()
            self.assertEqual(find_chromium_database(profile), database.resolve())

    def test_exact_runner_stages_an_isolated_registry_profile_and_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "seeded"
            database = source / "Default/Network/Cookies"
            database.parent.mkdir(parents=True)
            database.touch()
            (source / "Local State").write_text("{}", encoding="utf-8")
            staged, environment, profile_id = stage_discovered_profile(
                "chromium", "chrome", source
            )
            self.assertTrue((staged / "Default/Network/Cookies").is_file())
            self.assertTrue(staged.is_relative_to(Path(environment["HOME"])))
            self.assertEqual(len(profile_id), 64)
            self.assertTrue(
                all(character in "0123456789abcdef" for character in profile_id)
            )


if __name__ == "__main__":
    unittest.main()
