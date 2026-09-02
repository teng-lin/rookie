#!/usr/bin/env python3
"""Materializes the isolation collision corpus as real browser-shaped SQLite
databases.

Reads `corpus.json` (the hand-authored oracle next to this file) and writes,
per named store, a Chromium `Cookies` database (schema 24: `meta` with
`version`/`last_compatible_version`, and a `cookies` table carrying the
columns this crate's Chromium extraction reads -- see
`tests/python/export_contract.py` and `tests/e2e/run_partition_context_e2e.py`
for the column list this mirrors, and `rookie-rs/src/browser/chromium/tests.rs`
for the `CREATE TABLE` shape) or a Firefox `cookies.sqlite` database
(`PRAGMA user_version = 16`, `moz_cookies` with `originAttributes` -- see
`rookie-rs/src/browser/mozilla.rs` test helpers and
`tests/python/test_binding_runtime.py`'s `_seed_gecko`).

stdlib only, deliberately: this corpus is a cross-language oracle and must
build without any of the crate's own tooling.

Usage:
    python3 build_isolation_corpus.py --out-dir DIR [--write-node-fixtures]
"""
from __future__ import annotations

import argparse
import base64
import json
import sqlite3
from pathlib import Path
from typing import Any

CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"

CHROMIUM_SCHEMA_VERSION = 24
CHROMIUM_LAST_COMPATIBLE_VERSION = 24
FIREFOX_USER_VERSION = 16

CHROMIUM_COLUMNS = [
    "host_key",
    "name",
    "value",
    "path",
    "is_secure",
    "is_httponly",
    "samesite",
    "expires_utc",
    "top_frame_site_key",
    "has_cross_site_ancestor",
    "source_scheme",
    "source_port",
    "is_persistent",
    "encrypted_value",
]

FIREFOX_COLUMNS = [
    "host",
    "name",
    "value",
    "path",
    "isSecure",
    "isHttpOnly",
    "sameSite",
    "expiry",
    "originAttributes",
]


def load_corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def build_chromium_store(store: dict[str, Any], path: Path) -> None:
    """Writes a Chromium `Cookies` SQLite database for one corpus store.

    `encrypted_value` is always empty and `value` is always plaintext, so no
    OS keychain/DPAPI decryption is needed to read this store back.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(
            """
            CREATE TABLE meta (key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);
            CREATE TABLE cookies (
              host_key TEXT NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              path TEXT NOT NULL,
              is_secure INTEGER NOT NULL,
              is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL,
              expires_utc INTEGER NOT NULL,
              top_frame_site_key TEXT,
              has_cross_site_ancestor INTEGER,
              source_scheme INTEGER,
              source_port INTEGER,
              is_persistent INTEGER,
              encrypted_value BLOB NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO meta (key, value) VALUES ('version', ?)",
            (str(CHROMIUM_SCHEMA_VERSION),),
        )
        connection.execute(
            "INSERT INTO meta (key, value) VALUES ('last_compatible_version', ?)",
            (str(CHROMIUM_LAST_COMPATIBLE_VERSION),),
        )
        placeholders = ", ".join("?" for _ in CHROMIUM_COLUMNS)
        insert = f"INSERT INTO cookies ({', '.join(CHROMIUM_COLUMNS)}) VALUES ({placeholders})"
        for row in store["rows"]:
            values = [row.get(column) for column in CHROMIUM_COLUMNS if column != "encrypted_value"]
            values.append(b"")
            connection.execute(insert, values)
        connection.commit()
    finally:
        connection.close()


def build_firefox_store(store: dict[str, Any], path: Path) -> None:
    """Writes a Firefox `cookies.sqlite` database for one corpus store."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(f"PRAGMA user_version = {FIREFOX_USER_VERSION}")
        connection.execute(
            """
            CREATE TABLE moz_cookies (
              host TEXT NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              path TEXT NOT NULL,
              isSecure INTEGER NOT NULL,
              isHttpOnly INTEGER NOT NULL,
              sameSite INTEGER NOT NULL,
              expiry INTEGER NOT NULL,
              originAttributes TEXT NOT NULL
            )
            """
        )
        placeholders = ", ".join("?" for _ in FIREFOX_COLUMNS)
        insert = f"INSERT INTO moz_cookies ({', '.join(FIREFOX_COLUMNS)}) VALUES ({placeholders})"
        for row in store["rows"]:
            values = [row.get(column) for column in FIREFOX_COLUMNS]
            connection.execute(insert, values)
        connection.commit()
    finally:
        connection.close()


def build_store(corpus: dict[str, Any], store_name: str, path: Path) -> None:
    """Writes the named corpus store's database to `path`.

    Dispatches on `stores.<store_name>.engine` ("chromium" or "firefox").
    """
    store = corpus["stores"][store_name]
    engine = store["engine"]
    if engine == "chromium":
        build_chromium_store(store, path)
    elif engine == "firefox":
        build_firefox_store(store, path)
    else:
        raise ValueError(f"unknown engine {engine!r} for store {store_name!r}")


def build_all_stores(corpus: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for store_name in corpus["stores"]:
        path = out_dir / f"{store_name}.sqlite"
        build_store(corpus, store_name, path)
        paths[store_name] = path
    return paths


NODE_FIXTURE_STORES = {
    "chromium_isolated": "isolation-corpus-chromium.sqlite.base64",
    "firefox_isolated": "isolation-corpus-firefox.sqlite.base64",
    "firefox_unknown_attr": "isolation-corpus-firefox-unknown-attr.sqlite.base64",
}


def write_node_fixture(paths: dict[str, Path], fixtures_dir: Path) -> None:
    """Writes the base64 fixtures `bindings/node/__test__` tests consume.

    Matches `installDatabaseFixture` in `bindings/node/__test__/index.spec.mjs`:
    plain base64 of the raw SQLite file, read with `readFileSync(..., "ascii")`
    and whitespace stripped before decoding, so line-wrapping is cosmetic only.
    """
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    for store_name, filename in NODE_FIXTURE_STORES.items():
        _write_base64(paths[store_name], fixtures_dir / filename)


def _write_base64(source: Path, dest: Path) -> None:
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    lines = [encoded[index : index + 76] for index in range(0, len(encoded), 76)]
    dest.write_text("\n".join(lines) + "\n", encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--write-node-fixtures",
        action="store_true",
        help="also write bindings/node/__test__/fixtures/isolation-corpus-*.sqlite.base64",
    )
    args = parser.parse_args()

    corpus = load_corpus()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    paths = build_all_stores(corpus, args.out_dir)

    if args.write_node_fixtures:
        repo_root = Path(__file__).resolve().parents[2]
        fixtures_dir = repo_root / "bindings" / "node" / "__test__" / "fixtures"
        write_node_fixture(paths, fixtures_dir)
        print(f"wrote node fixtures to {fixtures_dir}")

    for name, path in paths.items():
        print(f"wrote {name} -> {path}")


if __name__ == "__main__":
    main()
