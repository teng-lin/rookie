"""Tests for the SQLite snapshot guard used by the App-Bound canary."""

from __future__ import annotations

from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT_PATH = Path(__file__).with_name("hold_sqlite_snapshot.py")


class HoldSqliteSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookie WAL guard ")
        self.root = Path(self.tempdir.name)
        self.database = self.root / "Chromium Profile" / "Cookies"
        self.database.parent.mkdir()
        self.ready_file = self.root / "guard.ready"
        self.stop_file = self.root / "guard.stop"
        self.process: subprocess.Popen[str] | None = None

        connection = sqlite3.connect(self.database)
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            self.assertEqual(mode, ("delete",))
            connection.execute("CREATE TABLE cookies (name TEXT NOT NULL)")
            connection.execute("INSERT INTO cookies VALUES ('baseline')")
            connection.commit()
        finally:
            connection.close()

    def tearDown(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)
        self.tempdir.cleanup()

    def start_guard(self) -> None:
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(SCRIPT_PATH),
                str(self.database),
                "--ready-file",
                str(self.ready_file),
                "--stop-file",
                str(self.stop_file),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.ready_file.is_file():
                return
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate()
                self.fail(
                    f"snapshot guard exited early ({self.process.returncode}): "
                    f"{stdout}{stderr}"
                )
            time.sleep(0.05)
        self.fail("snapshot guard did not become ready")

    def test_holds_later_commit_out_of_main_database(self) -> None:
        self.start_guard()

        writer = sqlite3.connect(self.database)
        try:
            writer.execute("INSERT INTO cookies VALUES ('wal-only')")
            writer.commit()
        finally:
            writer.close()

        wal_path = Path(f"{self.database}-wal")
        self.assertTrue(wal_path.is_file())
        self.assertGreater(wal_path.stat().st_size, 0)

        main_database_copy = self.root / "Cookies-main-only"
        shutil.copyfile(self.database, main_database_copy)
        main_only = sqlite3.connect(main_database_copy)
        try:
            main_rows = main_only.execute("SELECT name FROM cookies").fetchall()
        finally:
            main_only.close()
        self.assertEqual(main_rows, [("baseline",)])

        live = sqlite3.connect(self.database)
        try:
            mode = live.execute("PRAGMA journal_mode").fetchone()
            live_rows = live.execute("SELECT name FROM cookies").fetchall()
        finally:
            live.close()
        self.assertEqual(mode, ("wal",))
        self.assertEqual(live_rows, [("baseline",), ("wal-only",)])

        self.stop_file.write_text("stop\n", encoding="utf-8")
        assert self.process is not None
        stdout, stderr = self.process.communicate(timeout=5)
        self.assertEqual(self.process.returncode, 0, stderr)
        self.assertIn("Holding SQLite read snapshot", stdout)


if __name__ == "__main__":
    unittest.main()
