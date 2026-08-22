"""Synthetic tests for the active-writer coordinator; no browser profiles."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import run_active_writer_e2e as active
from cookie_state import assert_cookie_state


class ActiveWriterProtocolTests(unittest.TestCase):
    def make_chromium_db(self, root: Path) -> Path:
        database = root / "Default/Network/Cookies"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        connection.execute("create table meta (key text, value text)")
        connection.execute("insert into meta values ('version', '24')")
        connection.execute("create table cookies (name text, value text)")
        connection.executemany(
            "insert into cookies values (?, ?)",
            [("rookie_ci", "before"), ("rookie_remove", "present")],
        )
        connection.commit()
        connection.close()
        return database

    def test_ready_ack_proves_exact_active_profile_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            database = self.make_chromium_db(profile)
            process = mock.Mock(spec=subprocess.Popen)
            process.pid = 4321
            process.poll.return_value = None
            ack = {
                "engine": "chromium",
                "phase": "ready",
                "profileDir": str(profile.resolve()),
                "databasePath": str(database.resolve()),
                # The coordinator may be an xvfb-run wrapper, so the Node
                # seeder PID is independently acknowledged and checked alive.
                "seederPid": os.getpid(),
                "browserProcessIds": [os.getpid()],
                "liveness": {"readyState": "complete"},
            }
            self.assertEqual(
                active.validate_profile_proof(ack, "chromium", profile, process),
                database.resolve(),
            )

    def test_ready_ack_rejects_database_outside_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "profile"
            self.make_chromium_db(profile)
            outside = root / "outside.sqlite"
            outside.touch()
            process = mock.Mock(spec=subprocess.Popen)
            process.pid = 4321
            process.poll.return_value = None
            ack = {
                "engine": "chromium",
                "phase": "ready",
                "profileDir": str(profile.resolve()),
                "databasePath": str(outside.resolve()),
                "seederPid": os.getpid(),
                "browserProcessIds": [os.getpid()],
                "liveness": {},
            }
            with self.assertRaisesRegex(active.ActiveWriterError, "database mismatch"):
                active.validate_profile_proof(ack, "chromium", profile, process)

    def test_ready_ack_requires_a_live_browser_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            database = self.make_chromium_db(profile)
            process = mock.Mock(spec=subprocess.Popen)
            process.poll.return_value = None
            ack = {
                "engine": "chromium",
                "phase": "ready",
                "profileDir": str(profile.resolve()),
                "databasePath": str(database.resolve()),
                "seederPid": os.getpid(),
                "browserProcessIds": [],
                "liveness": {"readyState": "complete"},
            }
            with self.assertRaisesRegex(
                active.ActiveWriterError, "browser process owning"
            ):
                active.validate_profile_proof(ack, "chromium", profile, process)

    def test_database_metadata_reports_schema_journal_and_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = self.make_chromium_db(Path(tmp))
            Path(f"{database}-wal").touch()
            metadata = active.database_metadata(database, "chromium")
            self.assertEqual(metadata["browserSchemaVersion"], 24)
            self.assertIn(metadata["journalMode"], {"delete", "wal"})
            self.assertTrue(metadata["walPresent"])

    def test_storage_transition_requires_add_replace_subject_and_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = self.make_chromium_db(Path(tmp))
            active.wait_for_storage_names(
                database,
                "chromium",
                active.BASELINE_REQUIRED,
                active.BASELINE_FORBIDDEN,
                0.2,
            )
            connection = sqlite3.connect(database)
            connection.execute(
                "update cookies set value = 'after' where name = 'rookie_ci'"
            )
            connection.execute("delete from cookies where name = 'rookie_remove'")
            connection.execute("insert into cookies values ('rookie_added', 'present')")
            connection.commit()
            connection.close()
            active.wait_for_storage_names(
                database,
                "chromium",
                active.MUTATED_REQUIRED,
                active.MUTATED_FORBIDDEN,
                0.2,
            )

    def test_cookie_state_rejects_duplicate_and_deleted_rows(self) -> None:
        with self.assertRaisesRegex(AssertionError, "exactly one"):
            assert_cookie_state(
                [
                    {"name": "rookie_ci", "value": "after"},
                    {"name": "rookie_ci", "value": "after"},
                ],
                {"rookie_ci": "after"},
                [],
                surface="synthetic",
            )
        with self.assertRaisesRegex(AssertionError, "forbidden/deleted"):
            assert_cookie_state(
                [
                    {"name": "rookie_ci", "value": "after"},
                    {"name": "rookie_remove", "value": "present"},
                ],
                {"rookie_ci": "after"},
                ["rookie_remove"],
                surface="synthetic",
            )

    def test_exact_cookie_state_rejects_unrelated_rows(self) -> None:
        with mock.patch.dict(os.environ, {"ROOKIE_E2E_EXACT_COOKIE_STATE": "1"}):
            with self.assertRaisesRegex(AssertionError, "exact active-writer set"):
                assert_cookie_state(
                    [
                        {"name": "rookie_ci", "value": "after"},
                        {"name": "unrelated", "value": "leak"},
                    ],
                    {"rookie_ci": "after"},
                    [],
                    surface="synthetic",
                )

    def test_ack_wait_fails_closed_on_seeder_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp)
            (control / "error.json").write_text(
                json.dumps({"message": "synthetic failure"}), encoding="utf-8"
            )
            process = mock.Mock(spec=subprocess.Popen)
            process.poll.return_value = None
            with self.assertRaisesRegex(active.ActiveWriterError, "synthetic failure"):
                active.wait_for_ack(control, 0, process, 0.1)

    def test_seeder_commands_never_target_default_user_profiles(self) -> None:
        profile = Path("/workspace/scoped-profile")
        control = Path("/workspace/control")
        command = active.build_seeder_command(
            "chromium",
            profile,
            "http://127.0.0.1:9000/active-writer/baseline",
            control,
            "chrome",
            False,
        )
        self.assertIn(str(profile), command)
        self.assertIn(str(control), command)
        self.assertNotIn("--browser", command)


if __name__ == "__main__":
    unittest.main()
