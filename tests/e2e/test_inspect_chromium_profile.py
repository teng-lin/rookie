"""Tests for lock-free WAL inspection used by the App-Bound canary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


def load_module(name: str, filename: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


INSPECT = load_module("inspect_chromium_profile", "inspect_chromium_profile.py")


class InspectChromiumProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookie WAL fixture ")
        self.database = Path(self.tempdir.name) / "Chromium Profile" / "Cookies"
        self.database.parent.mkdir()

        connection = sqlite3.connect(self.database)
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()
            self.assertEqual(mode, ("delete",))
            connection.execute(
                "CREATE TABLE cookies ("
                "host_key TEXT NOT NULL, name TEXT NOT NULL, "
                "encrypted_value BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT INTO cookies VALUES (?, ?, ?)",
                ("127.0.0.1", "baseline", b"v20" + bytes(28)),
            )
            connection.commit()
        finally:
            connection.close()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_exclusive_writer_can_commit_and_snapshot_stays_lock_free(self) -> None:
        setup = sqlite3.connect(self.database)
        try:
            mode = setup.execute("PRAGMA journal_mode=WAL").fetchone()
            self.assertEqual(mode, ("wal",))
        finally:
            setup.close()

        writer = sqlite3.connect(self.database, timeout=0.25)
        try:
            mode = writer.execute("PRAGMA locking_mode=EXCLUSIVE").fetchone()
            self.assertEqual(mode, ("exclusive",))
            writer.execute(
                "INSERT INTO cookies VALUES (?, ?, ?)",
                ("127.0.0.1", "wal-only", b"v20" + bytes(28)),
            )
            writer.commit()

            blocked_reader = sqlite3.connect(self.database, timeout=0.05)
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    blocked_reader.execute("SELECT count(*) FROM cookies").fetchone()
            finally:
                blocked_reader.close()

            main_rows, snapshot_rows = INSPECT.wal_snapshot_cookie_rows(
                self.database, "wal-only"
            )
        finally:
            writer.close()

        self.assertEqual(main_rows, [])
        self.assertEqual(
            snapshot_rows,
            [("127.0.0.1", "wal-only", "763230", 31)],
        )


if __name__ == "__main__":
    unittest.main()
