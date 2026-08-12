"""Hold a read snapshot open so later SQLite writes remain in the WAL."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from pathlib import Path


def hold_snapshot(database: Path, ready_file: Path, stop_file: Path) -> None:
    uri = f"{database.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("BEGIN")
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        if journal_mode != ("wal",):
            actual = journal_mode[0] if journal_mode else "unknown"
            raise ValueError(f"expected WAL journal mode, found {actual!r}")

        # A read must occur after BEGIN to pin a snapshot. A later writer can
        # still commit, but SQLite cannot checkpoint those frames past this
        # reader's end mark until the connection closes.
        connection.execute("SELECT count(*) FROM cookies").fetchone()
        ready_file.write_text("ready\n", encoding="utf-8")
        print(f"Holding SQLite read snapshot for {database}", flush=True)

        while not stop_file.exists():
            time.sleep(0.1)
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        hold_snapshot(args.database, args.ready_file, args.stop_file)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"SQLite snapshot guard failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
