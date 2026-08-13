"""Stage a copied Chromium cookie row in a fixture's WAL sidecar."""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from pathlib import Path


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def stage_wal_cookie(
    source_database: Path,
    fixture_database: Path,
    source_cookie: str,
    fixture_cookie: str,
) -> sqlite3.Connection:
    fixture_database.parent.mkdir(parents=True, exist_ok=True)
    for path in (
        fixture_database,
        Path(f"{fixture_database}-wal"),
        Path(f"{fixture_database}-shm"),
    ):
        path.unlink(missing_ok=True)
    shutil.copyfile(source_database, fixture_database)

    connection = sqlite3.connect(fixture_database)
    journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
    if journal_mode != ("wal",):
        actual = journal_mode[0] if journal_mode else "unknown"
        raise ValueError(f"could not enable WAL journal mode, found {actual!r}")
    connection.execute("PRAGMA wal_autocheckpoint=0")

    columns = [
        str(row[1]) for row in connection.execute("PRAGMA table_info(cookies)")
    ]
    if "name" not in columns:
        raise ValueError("cookies table has no name column")
    quoted_columns = ", ".join(quote_identifier(column) for column in columns)
    selected_columns = ", ".join(
        "?" if column == "name" else quote_identifier(column) for column in columns
    )
    inserted = connection.execute(
        f"INSERT INTO cookies ({quoted_columns}) "
        f"SELECT {selected_columns} FROM cookies WHERE name = ? LIMIT 1",
        (fixture_cookie, source_cookie),
    )
    if inserted.rowcount != 1:
        raise ValueError(f"source cookie {source_cookie!r} was not found")
    connection.commit()
    return connection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_database", type=Path)
    parser.add_argument("fixture_database", type=Path)
    parser.add_argument("--source-cookie", required=True)
    parser.add_argument("--fixture-cookie", required=True)
    args = parser.parse_args(argv)

    connection: sqlite3.Connection | None = None
    try:
        connection = stage_wal_cookie(
            args.source_database,
            args.fixture_database,
            args.source_cookie,
            args.fixture_cookie,
        )
        wal_path = Path(f"{args.fixture_database}-wal")
        print(
            f"Staged {args.fixture_cookie!r} in {wal_path} "
            f"({wal_path.stat().st_size} bytes)",
            flush=True,
        )
    except (OSError, ValueError, sqlite3.Error) as error:
        if connection is not None:
            connection.close()
        print(f"SQLite WAL fixture staging failed: {error}", file=sys.stderr)
        return 1

    # SQLite checkpoints and removes the WAL when the last connection closes.
    # This helper is a short-lived fixture writer, so exit without destructors
    # after the committed WAL has reached disk.
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
