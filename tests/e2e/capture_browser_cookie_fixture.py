#!/usr/bin/env python3
"""Create a sanitized, provenance-rich cookie fixture candidate.

This tool deliberately refuses to read an arbitrary browser profile. The
caller must point it at a disposable source root containing a marker created by
the E2E capture workflow. Only cookie rows declared by an independent manifest
survive; every other user table is emptied before SQLite compacts the result.

The output is a review candidate, not an automatically trusted golden. Never
pass a real user profile to this command.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import platform as host_platform
import shutil
import sqlite3
import sys
import tempfile
from typing import Any, Iterable

from browser_coverage_contract import emit_representative_depth
from cookie_manifest import ManifestError, load_manifest, verify_records


MARKER_NAME = ".rookie-cookie-fixture-source.json"
MARKER_KIND = "rookie-cookie-fixture-source"
SCHEMA_VERSION = 1


class CaptureError(RuntimeError):
    """Raised when a fixture candidate cannot be proven safe and complete."""


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def require_disposable_source(source_root: Path, database: Path) -> dict[str, Any]:
    source_root = source_root.resolve()
    database = database.resolve()
    try:
        database.relative_to(source_root)
    except ValueError as error:
        raise CaptureError("source database must be inside --source-root") from error

    marker_path = source_root / MARKER_NAME
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise CaptureError(
            f"refusing unmarked source root; create {marker_path} in a disposable profile"
        ) from error
    except json.JSONDecodeError as error:
        raise CaptureError(f"invalid disposable-source marker: {error}") from error

    if not isinstance(marker, dict) or marker.get("kind") != MARKER_KIND:
        raise CaptureError(f"{marker_path} is not a {MARKER_KIND!r} marker")
    if marker.get("schema_version") != SCHEMA_VERSION:
        raise CaptureError(
            f"unsupported marker schema_version {marker.get('schema_version')!r}"
        )
    if not database.is_file():
        raise CaptureError(f"source database does not exist: {database}")
    return marker


def load_expected_rows(path: Path, engine: str) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CaptureError(f"expected manifest is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise CaptureError("expected manifest must be an object")

    manifest_engine = document.get("engine")
    if manifest_engine not in (None, engine):
        raise CaptureError(
            f"expected manifest engine was {manifest_engine!r}, requested {engine!r}"
        )
    records = document.get("cookies")
    if not isinstance(records, list):
        expected = document.get("expected")
        if isinstance(expected, dict):
            records = expected.get("detailed")
    if not isinstance(records, list) or not records:
        raise CaptureError(
            "expected manifest must contain a non-empty cookies array or expected.detailed"
        )

    rows: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise CaptureError(f"cookies[{index}] must be an object")
        cookie = record.get("cookie", record)
        context = record.get("context", {})
        if not isinstance(cookie, dict) or not isinstance(context, dict):
            raise CaptureError(f"cookies[{index}] has invalid cookie/context objects")
        required = ("domain", "path", "name")
        if any(not isinstance(cookie.get(key), str) for key in required):
            raise CaptureError(
                f"cookies[{index}] must contain string domain, path, and name"
            )
        row = {
            "domain": cookie["domain"],
            "path": cookie["path"],
            "name": cookie["name"],
        }
        if engine == "chromium":
            row["partition_key"] = (
                context.get("top_frame_site_key")
                or context.get("topFrameSiteKey")
                or ""
            )
            ancestor = context.get(
                "has_cross_site_ancestor", context.get("hasCrossSiteAncestor")
            )
            row["has_cross_site_ancestor"] = 0 if ancestor in (None, False) else 1
        else:
            row["origin_attributes"] = (
                context.get("origin_attributes")
                or context.get("originAttributes")
                or ""
            )
        rows.append(row)
    return rows, hashlib.sha256(raw).hexdigest()


def table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    quoted = quote_identifier(table)
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_xinfo({quoted})")}


def cookie_table(engine: str) -> str:
    return "cookies" if engine == "chromium" else "moz_cookies"


def actual_cookie_rows(
    connection: sqlite3.Connection, engine: str, *, include_rowid: bool = False
) -> list[dict[str, Any]]:
    table = cookie_table(engine)
    columns = table_columns(connection, table)
    if engine == "chromium":
        required = {"host_key", "path", "name"}
        if not required.issubset(columns):
            raise CaptureError(
                f"Chromium cookies table is missing {sorted(required - columns)}"
            )
        partition = "top_frame_site_key" if "top_frame_site_key" in columns else "''"
        ancestor = (
            "has_cross_site_ancestor" if "has_cross_site_ancestor" in columns else "0"
        )
        query = (
            "SELECT rowid, host_key, path, name, "
            f"COALESCE({partition}, ''), COALESCE({ancestor}, 0) FROM cookies"
        )
        result = []
        for (
            rowid,
            domain,
            path,
            name,
            partition_key,
            has_ancestor,
        ) in connection.execute(query):
            row = {
                "domain": str(domain),
                "path": str(path),
                "name": str(name),
                "partition_key": str(partition_key),
                "has_cross_site_ancestor": int(has_ancestor),
            }
            if include_rowid:
                row["_rowid"] = int(rowid)
            result.append(row)
        return result

    required = {"host", "path", "name"}
    if not required.issubset(columns):
        raise CaptureError(
            f"Firefox cookies table is missing {sorted(required - columns)}"
        )
    origin = "originAttributes" if "originAttributes" in columns else "''"
    origin_expression = quote_identifier(origin) if origin != "''" else origin
    query = (
        "SELECT rowid, host, path, name, "
        f"COALESCE({origin_expression}, '') "
        "FROM moz_cookies"
    )
    result = []
    for rowid, domain, path, name, origin_attributes in connection.execute(query):
        row = {
            "domain": str(domain),
            "path": str(path),
            "name": str(name),
            "origin_attributes": str(origin_attributes),
        }
        if include_rowid:
            row["_rowid"] = int(rowid)
        result.append(row)
    return result


def user_tables(connection: sqlite3.Connection) -> list[str]:
    return [
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


def schema_signature(connection: sqlite3.Connection) -> dict[str, Any]:
    objects = [
        {"type": row[0], "name": row[1], "table": row[2], "sql": row[3]}
        for row in connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        )
    ]
    columns = {
        table: [
            list(row)
            for row in connection.execute(
                f"PRAGMA table_xinfo({quote_identifier(table)})"
            )
        ]
        for table in user_tables(connection)
    }
    meta: dict[str, str] = {}
    if "meta" in columns and {"key", "value"}.issubset(
        table_columns(connection, "meta")
    ):
        meta = {
            str(key): str(value)
            for key, value in connection.execute(
                "SELECT key, value FROM meta "
                "WHERE key IN ('version', 'compatible_version') ORDER BY key"
            )
        }
    return {
        "objects": objects,
        "columns": columns,
        "meta": meta,
        "sqlite_schema_version": int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        ),
        "sqlite_user_version": int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        ),
        "sqlite_page_size": int(connection.execute("PRAGMA page_size").fetchone()[0]),
    }


def verify_decoded_cookies(manifest_path: Path, decoded_path: Path) -> tuple[int, str]:
    """Require a public decoder's full detailed output to match the manifest."""

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as error:
        raise CaptureError(str(error)) from error
    try:
        decoded = json.loads(decoded_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CaptureError(
            f"decoded cookie output is not valid JSON: {error}"
        ) from error
    if not isinstance(decoded, list):
        raise CaptureError("decoded cookie output must be a JSON array")
    try:
        count = verify_records(
            manifest,
            "detailed",
            decoded,
            surface="fixture capture decoded output",
        )
    except ManifestError as error:
        raise CaptureError(str(error)) from error
    return count, sha256_file(decoded_path)


def empty_non_cookie_tables(connection: sqlite3.Connection, engine: str) -> None:
    keep_rows = {cookie_table(engine)}
    if engine == "chromium":
        keep_rows.add("meta")
    for table in user_tables(connection):
        if table not in keep_rows:
            connection.execute(f"DELETE FROM {quote_identifier(table)}")
    if engine == "chromium" and "meta" in user_tables(connection):
        connection.execute(
            "DELETE FROM meta WHERE key NOT IN ('version', 'compatible_version')"
        )


def delete_unexpected_cookies(
    connection: sqlite3.Connection,
    engine: str,
    expected: Iterable[dict[str, Any]],
) -> None:
    remaining = Counter(tuple(sorted(row.items())) for row in expected)
    delete_rowids: list[int] = []
    for observed in actual_cookie_rows(connection, engine, include_rowid=True):
        rowid = int(observed.pop("_rowid"))
        identity = tuple(sorted(observed.items()))
        if remaining[identity] > 0:
            remaining[identity] -= 1
        else:
            delete_rowids.append(rowid)
    table = quote_identifier(cookie_table(engine))
    connection.executemany(
        f"DELETE FROM {table} WHERE rowid = ?", ((rowid,) for rowid in delete_rowids)
    )


def sanitize_database(
    source: Path, output: Path, engine: str, expected: list[dict[str, Any]]
) -> dict[str, Any]:
    if output.exists():
        raise CaptureError(f"refusing to overwrite existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="rookie-cookie-capture-") as temp:
        staged = Path(temp) / "sanitized.sqlite"
        source_uri = f"{source.resolve().as_uri()}?mode=ro"
        reader = sqlite3.connect(source_uri, uri=True)
        writer = sqlite3.connect(staged)
        try:
            reader.backup(writer)
        finally:
            reader.close()
            writer.close()

        connection = sqlite3.connect(staged)
        try:
            connection.execute("PRAGMA secure_delete = ON")
            before = actual_cookie_rows(connection, engine)
            delete_unexpected_cookies(connection, engine, expected)
            empty_non_cookie_tables(connection, engine)
            connection.commit()
            after = actual_cookie_rows(connection, engine)
            if Counter(tuple(sorted(row.items())) for row in after) != Counter(
                tuple(sorted(row.items())) for row in expected
            ):
                raise CaptureError(
                    "sanitized database rows do not exactly match the expected manifest: "
                    f"expected={expected!r}, actual={after!r}"
                )
            signature = schema_signature(connection)
            connection.execute("VACUUM")
        finally:
            connection.close()

        shutil.copyfile(staged, output)

    return {
        "source_cookie_rows": len(before),
        "retained_cookie_rows": len(expected),
        "schema": signature,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-database", type=Path, required=True)
    parser.add_argument("--output-database", type=Path, required=True)
    parser.add_argument("--expected-manifest", type=Path, required=True)
    parser.add_argument("--decoded-cookies", type=Path, required=True)
    parser.add_argument("--provenance-output", type=Path, required=True)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--browser-version", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--browser-channel", required=True)
    parser.add_argument("--browser-source", required=True)
    parser.add_argument("--capture-command", required=True)
    parser.add_argument("--sanitizer-revision", required=True)
    parser.add_argument("--platform", default=sys.platform)
    parser.add_argument("--architecture", default=host_platform.machine())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        source_root = args.source_root.resolve()
        source_database = args.source_database.resolve()
        output_database = args.output_database.resolve()
        provenance_output = args.provenance_output.resolve()
        marker = require_disposable_source(source_root, source_database)
        for destination in (output_database, provenance_output):
            try:
                destination.relative_to(source_root)
            except ValueError:
                pass
            else:
                raise CaptureError("outputs must be outside the disposable source root")
            if destination.exists():
                raise CaptureError(
                    f"refusing to overwrite existing output: {destination}"
                )

        expected, manifest_digest = load_expected_rows(
            args.expected_manifest, args.engine
        )
        decoded_count, decoded_digest = verify_decoded_cookies(
            args.expected_manifest, args.decoded_cookies
        )
        capture = sanitize_database(
            source_database, output_database, args.engine, expected
        )
        provenance = {
            "schema_version": SCHEMA_VERSION,
            "browser": args.browser,
            "browser_version": args.browser_version,
            "build_id": args.build_id,
            "browser_channel": args.browser_channel,
            "browser_source": args.browser_source,
            "engine": args.engine,
            "platform": args.platform,
            "architecture": args.architecture,
            "source_kind": marker.get("source_kind", "disposable_e2e_profile"),
            "expected_manifest_sha256": manifest_digest,
            "decoded_output_sha256": decoded_digest,
            "decoded_cookie_rows": decoded_count,
            "fixture_sha256": sha256_file(output_database),
            "fixture_bytes": output_database.stat().st_size,
            "source_database_bytes": source_database.stat().st_size,
            "capture_command": args.capture_command,
            "sanitizer_revision": args.sanitizer_revision,
            "retained_identities": expected,
            **capture,
        }
        provenance_output.parent.mkdir(parents=True, exist_ok=True)
        provenance_output.write_bytes(canonical_json(provenance))
        print(
            f"captured {capture['retained_cookie_rows']} sanitized {args.engine} "
            f"rows in {output_database}; provenance: {provenance_output}"
        )
        emit_representative_depth(
            "manual_fixture_capture", ("browser_launch", "detailed"), ()
        )
    except (AssertionError, CaptureError, OSError, sqlite3.Error, ValueError) as error:
        print(f"browser fixture capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
