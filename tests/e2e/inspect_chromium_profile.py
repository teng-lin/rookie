"""Print non-secret Chromium crypto diagnostics and enforce CI invariants."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path


def cookie_db(user_data_dir: Path) -> Path:
    for relative in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = user_data_dir / relative
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no Cookies database below {user_data_dir / 'Default'}")


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


def main() -> int:
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
            wal_path = Path(f"{db_path}-wal")
            if not wal_path.is_file() or wal_path.stat().st_size == 0:
                raise ValueError(f"Cookies WAL is missing or empty: {wal_path}")
            with tempfile.TemporaryDirectory(prefix="rookie-main-db-") as temp_dir:
                main_db_copy = Path(temp_dir) / "Cookies"
                shutil.copyfile(db_path, main_db_copy)
                main_rows = cookie_rows(main_db_copy, args.cookie_name)
            if main_rows:
                raise ValueError(
                    f"{args.cookie_name!r} is already present in the main Cookies DB"
                )
            print(
                f"{args.cookie_name} is absent from the main DB copy and must be read "
                "through the live WAL"
            )

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
