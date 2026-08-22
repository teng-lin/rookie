from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from run_active_writer_e2e import ActiveWriterError
from run_browser_cookie_stress_e2e import (
    locked_database_copy,
    raw_write_generation,
    require_ci_sandbox,
    surface_commands,
    validate_stress_profile_proof,
    wait_for_mutation,
    wait_for_stress_rows,
)
from run_exact_corpus_e2e import find_chromium_database, stage_discovered_profile
from run_partition_context_e2e import (
    _firefox_expiry,
    discovery_layout,
    require_remote_sandbox,
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

    def test_partition_discovery_layout_uses_platform_registry_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = Path(temporary)
            executable = sandbox / "firefox"
            executable.touch()
            with mock.patch(
                "run_partition_context_e2e.playwright_executable",
                return_value=str(executable),
            ):
                profile, environment = discovery_layout("firefox", sandbox)
            registry_root = profile.parent.parent
            profiles_ini = registry_root / "profiles.ini"
            self.assertTrue(profiles_ini.is_file())
            self.assertTrue(profile.is_relative_to(Path(environment["HOME"])))
            self.assertEqual(environment["ROOKIE_E2E_BROWSER_PATH"], str(executable))
            if sys.platform == "darwin":
                self.assertNotIn("snap/firefox", str(profile))

    def test_partition_oracle_normalizes_firefox_schema_16_milliseconds(self) -> None:
        self.assertEqual(_firefox_expiry(1_700_000_000, 15), 1_700_000_000)
        self.assertEqual(_firefox_expiry(1_700_000_000_999, 16), 1_700_000_000)
        self.assertIsNone(_firefox_expiry(0, 17))

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
            payload["browserProcessIds"] = [21, 22]
            with mock.patch(
                "run_browser_cookie_stress_e2e.process_is_alive",
                side_effect=[False, True],
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

    def test_firefox_stress_uses_lock_safe_raw_storage_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "cookies.sqlite"
            database.touch()
            initial = raw_write_generation(database, "firefox")
            wal = Path(f"{database}-wal")
            wal.write_bytes(b"browser write")
            self.assertGreater(raw_write_generation(database, "firefox"), initial)

    def test_firefox_stress_accepts_only_a_genuine_live_sqlite_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "cookies.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("create table moz_cookies (name text)")
            connection.execute("begin exclusive")
            try:
                wait_for_stress_rows(
                    database,
                    "firefox",
                    1,
                    allow_locked_after=0,
                )
                wait_for_mutation(
                    database,
                    "firefox",
                    0,
                    1,
                    allow_locked_after=0,
                )
            finally:
                connection.execute("rollback")
                connection.close()

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

    def test_exact_runner_does_not_stage_firefox_process_lock_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "seeded"
            source.mkdir()
            (source / "cookies.sqlite").touch()
            for name in ("lock", ".parentlock", "parent.lock"):
                (source / name).touch()
            staged, _environment, profile_id = stage_discovered_profile(
                "firefox", "firefox", source
            )
            self.assertTrue((staged / "cookies.sqlite").is_file())
            for name in ("lock", ".parentlock", "parent.lock"):
                self.assertFalse((staged / name).exists())
            self.assertEqual(len(profile_id), 64)


if __name__ == "__main__":
    unittest.main()
