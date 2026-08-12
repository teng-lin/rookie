"""Print non-secret Chromium crypto diagnostics and enforce CI invariants."""

from __future__ import annotations

import argparse
import base64
import filecmp
import json
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


def cookie_db(user_data_dir: Path) -> Path:
    for relative in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = user_data_dir / relative
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no Cookies database below {user_data_dir / 'Default'}")


def configure_utf8_output() -> None:
    """Keep diagnostics printable for Unicode Windows profile paths."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="backslashreplace")


def decode_key(local_state: dict[str, object], name: str, prefix: bytes) -> bytes:
    os_crypt = local_state.get("os_crypt")
    if not isinstance(os_crypt, dict) or not isinstance(os_crypt.get(name), str):
        raise ValueError(f"Local State has no os_crypt.{name}")
    decoded = base64.b64decode(os_crypt[name], validate=True)
    if not decoded.startswith(prefix):
        raise ValueError(
            f"os_crypt.{name} does not start with {prefix.decode('ascii')}"
        )
    return decoded


def cookie_rows(db_path: Path, cookie_name: str) -> list[tuple[object, ...]]:
    uri = f"{db_path.resolve().as_uri()}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        return list(
            connection.execute(
                "SELECT host_key, name, hex(substr(encrypted_value, 1, 3)), "
                "length(encrypted_value) FROM cookies WHERE name = ?",
                (cookie_name,),
            )
        )
    finally:
        connection.close()


def wal_snapshot_cookie_rows(
    db_path: Path, cookie_name: str
) -> tuple[list[tuple[object, ...]], list[tuple[object, ...]]]:
    """Read a verified raw DB+WAL copy without locking the live database."""
    wal_path = Path(f"{db_path}-wal")
    for attempt in range(1, 4):
        try:
            with tempfile.TemporaryDirectory(prefix="rookie-wal-snapshot-") as root:
                root_path = Path(root)
                main_only_dir = root_path / "main-only"
                snapshot_dir = root_path / "snapshot"
                main_only_dir.mkdir()
                snapshot_dir.mkdir()

                snapshot_db = snapshot_dir / "Cookies"
                main_only_db = main_only_dir / "Cookies"
                snapshot_wal = Path(f"{snapshot_db}-wal")
                shutil.copyfile(db_path, snapshot_db)
                shutil.copyfile(snapshot_db, main_only_db)
                shutil.copyfile(wal_path, snapshot_wal)
                if snapshot_wal.stat().st_size == 0:
                    raise ValueError(f"Cookies WAL is empty: {wal_path}")

                # A checkpoint is the only WAL-mode operation that changes the
                # main file. Comparing it after both copies brackets the raw
                # snapshot without acquiring a SQLite lock from Chrome.
                if not filecmp.cmp(db_path, snapshot_db, shallow=False):
                    if attempt < 3:
                        time.sleep(0.02 * attempt)
                        continue
                    raise ValueError(
                        "Cookies database was checkpointed during three snapshots"
                    )

                return (
                    cookie_rows(main_only_db, cookie_name),
                    cookie_rows(snapshot_db, cookie_name),
                )
        except FileNotFoundError:
            if attempt < 3:
                time.sleep(0.02 * attempt)
                continue
            raise ValueError(f"Cookies WAL is missing: {wal_path}") from None

    raise AssertionError("the bounded WAL snapshot loop always returns")


def main() -> int:
    configure_utf8_output()
    parser = argparse.ArgumentParser()
    parser.add_argument("user_data_dir", type=Path)
    parser.add_argument("--cookie-name", default="rookie_ci")
    parser.add_argument("--expected-prefix", choices=("v10", "v20"), required=True)
    parser.add_argument("--require-dpapi-key", action="store_true")
    parser.add_argument("--require-app-bound-key", action="store_true")
    parser.add_argument(
        "--require-wal-only",
        action="store_true",
        help="require the selected cookie to be absent from a copy of the main DB",
    )
    args = parser.parse_args()

    try:
        local_state_path = args.user_data_dir / "Local State"
        local_state = json.loads(local_state_path.read_text(encoding="utf-8"))
        if args.require_dpapi_key:
            key = decode_key(local_state, "encrypted_key", b"DPAPI")
            print(f"DPAPI Local State key present (decoded length: {len(key)})")
        if args.require_app_bound_key:
            key = decode_key(local_state, "app_bound_encrypted_key", b"APPB")
            print(f"App-Bound Local State key present (decoded length: {len(key)})")

        db_path = cookie_db(args.user_data_dir)
        if args.require_wal_only:
            main_rows, rows = wal_snapshot_cookie_rows(db_path, args.cookie_name)
            if main_rows:
                raise ValueError(
                    f"{args.cookie_name!r} is already present in the main Cookies DB"
                )
            print(
                f"{args.cookie_name} is absent from the main DB copy and must be read "
                "through the live WAL"
            )
        else:
            rows = cookie_rows(db_path, args.cookie_name)
        print(f"{args.cookie_name} encrypted_value diagnostics: {rows}")
        expected_hex = args.expected_prefix.encode("ascii").hex().upper()
        if not rows:
            raise ValueError(f"no {args.cookie_name!r} cookie row")
        if any(row[2] != expected_hex for row in rows):
            prefixes = sorted({row[2] for row in rows})
            raise ValueError(
                f"{args.cookie_name!r} prefix was {prefixes}, "
                f"expected only {args.expected_prefix!r}"
            )
        if any(not isinstance(row[3], int) or row[3] <= 3 for row in rows):
            raise ValueError(f"{args.cookie_name!r} has a truncated encrypted value")
        print(f"{args.cookie_name} uses {args.expected_prefix} encryption in {db_path}")
    except (
        FileNotFoundError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        sqlite3.Error,
    ) as error:
        print(f"Chromium profile check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
