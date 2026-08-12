"""Put a closed SQLite database in WAL mode before its browser reopens it."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path


def prepare_wal(database: Path) -> None:
    connection = sqlite3.connect(database)
    try:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
        if journal_mode != ("wal",):
            actual = journal_mode[0] if journal_mode else "unknown"
            raise ValueError(f"could not enable WAL journal mode, found {actual!r}")
    finally:
        connection.close()
    print(f"Enabled SQLite WAL mode for {database}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path)
    args = parser.parse_args(argv)

    try:
        prepare_wal(args.database)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"SQLite WAL preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
