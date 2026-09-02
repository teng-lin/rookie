"""Validates `corpus.json` and the store generator that materializes it.

Two kinds of checks:

1. `corpus.json` shape: every store referenced by a case exists, every
   `selected` id resolves to a real row in that case's store, row ids are
   unique and each row's `value` equals its own `id`, the demand-token
   vocabulary used anywhere in the corpus is drawn from the fixed,
   canonically ordered ADR 0006 Decision 5 list, and every omission code
   used is drawn from the fixed `SendOmissions` vocabulary (ADR 0006
   Decision 2). Every store also carries a `jar` verdict.
2. Generator determinism: a freshly built store has content identical (not
   byte-identical -- SQLite page layout is not a stable contract) to the
   store encoded in the committed Node base64 fixtures.

This does not exercise the Rust/Python/Node/CLI consumers of the corpus --
those land in later PRs (#331 program). Where the crate/binding under test
is already built, this module additionally does a best-effort check that the
generated stores can be opened by it; otherwise that check is skipped and
noted, never silently assumed.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[1]
CORPUS_PATH = ROOT / "corpus.json"
BUILD_SCRIPT = ROOT / "build_isolation_corpus.py"
NODE_FIXTURES_DIR = REPO_ROOT / "bindings" / "node" / "__test__" / "fixtures"

# ADR 0006 Decision 5: fixed, append-only, canonically ordered.
CANONICAL_TOKEN_ORDER = [
    "top_level_site",
    "user_context_id",
    "private_browsing_id",
    "first_party_domain",
    "gecko_view_session_context_id",
    "origin_attributes",
]

# ADR 0006 Decision 2: SendOmissions::entries() serialization order.
CANONICAL_OMISSION_ORDER = [
    "expired",
    "not_applicable",
    "same_site",
    "partition",
    "ancestor_chain_unknown",
    "unparsable_partition_key",
    "origin",
]

CHROMIUM_ROW_KEYS = {
    "id",
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
}

FIREFOX_ROW_KEYS = {
    "id",
    "host",
    "name",
    "value",
    "path",
    "isSecure",
    "isHttpOnly",
    "sameSite",
    "expiry",
    "originAttributes",
}


def load_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


class CorpusShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = load_corpus()

    def test_top_level_shape(self) -> None:
        self.assertEqual(self.corpus["schema_version"], 1)
        self.assertEqual(self.corpus["kind"], "isolation-collision-corpus")
        self.assertIsInstance(self.corpus["clock_epoch_seconds"], int)
        self.assertGreater(self.corpus["clock_epoch_seconds"], 0)
        self.assertIsInstance(self.corpus["stores"], dict)
        self.assertIsInstance(self.corpus["cases"], list)
        self.assertGreater(len(self.corpus["cases"]), 0)
        self.assertIsInstance(self.corpus["notes"], list)
        self.assertGreater(len(self.corpus["notes"]), 0)
        for note in self.corpus["notes"]:
            self.assertIsInstance(note, str)
            self.assertGreater(len(note), 0)

    def test_expected_stores_present(self) -> None:
        self.assertEqual(
            set(self.corpus["stores"].keys()),
            {
                "chromium_isolated",
                "chromium_plain",
                "firefox_isolated",
                "firefox_unknown_attr",
                "firefox_plain",
            },
        )

    def test_every_row_value_equals_its_id_and_ids_are_unique(self) -> None:
        seen: set[str] = set()
        for store_name, store in self.corpus["stores"].items():
            for row in store["rows"]:
                self.assertEqual(
                    row["value"], row["id"], f"{store_name}: row value must equal id"
                )
                self.assertNotIn(row["id"], seen, f"duplicate row id {row['id']!r}")
                seen.add(row["id"])

    def test_store_rows_have_engine_appropriate_columns(self) -> None:
        for store_name, store in self.corpus["stores"].items():
            engine = store["engine"]
            self.assertIn(engine, ("chromium", "firefox"))
            expected_keys = CHROMIUM_ROW_KEYS if engine == "chromium" else FIREFOX_ROW_KEYS
            for row in store["rows"]:
                self.assertEqual(
                    set(row.keys()),
                    expected_keys,
                    f"{store_name}/{row.get('id')}: unexpected column set",
                )

    def test_store_include_expired_is_boolean_when_present(self) -> None:
        for store_name, store in self.corpus["stores"].items():
            if "include_expired" not in store:
                continue
            self.assertIsInstance(
                store["include_expired"],
                bool,
                f"{store_name}: include_expired must be a boolean",
            )

    def test_every_store_has_a_jar_verdict(self) -> None:
        for store_name, store in self.corpus["stores"].items():
            self.assertIn("jar", store, f"{store_name} missing jar verdict")
            expect = store["jar"]["expect"]
            if expect == "ok":
                continue
            self.assertIn("error", expect, f"{store_name} jar verdict must be 'ok' or an error")
            error = expect["error"]
            self.assertEqual(error["code"], "isolation_loss_refused")
            self._assert_canonical_token_list(error["required"], store_name)
            self.assertGreater(len(error["required"]), 0)

    def test_cases_reference_real_stores_and_ids(self) -> None:
        stores = self.corpus["stores"]
        case_ids: set[str] = set()
        for case in self.corpus["cases"]:
            case_id = case["id"]
            self.assertNotIn(case_id, case_ids, f"duplicate case id {case_id!r}")
            case_ids.add(case_id)

            store_name = case["store"]
            self.assertIn(store_name, stores, f"{case_id}: unknown store {store_name!r}")
            store = stores[store_name]
            row_ids = {row["id"] for row in store["rows"]}

            expect = case["expect"]
            if "error" in expect:
                self.assertEqual(expect["error"]["code"], "incomplete_send_context")
                self._assert_canonical_token_list(expect["error"]["required"], case_id)
                self.assertGreater(len(expect["error"]["required"]), 0)
                continue

            self.assertIn("selected", expect, f"{case_id}: expect must have selected or error")
            self.assertIn("header", expect)
            self.assertIn("omitted", expect)
            for selected_id in expect["selected"]:
                self.assertIn(
                    selected_id, row_ids, f"{case_id}: selected id {selected_id!r} not in {store_name}"
                )
            self._assert_header_matches_selected(case_id, store, expect)
            for code in expect["omitted"]:
                self.assertIn(
                    code,
                    CANONICAL_OMISSION_ORDER,
                    f"{case_id}: omission code {code!r} not in the fixed vocabulary",
                )
                self.assertGreater(expect["omitted"][code], 0, f"{case_id}: {code} must be non-zero")
            # Serialization order (ADR 0006 Decision 2): entries() order, not
            # attribution order. A dict literal preserves insertion order in
            # every JSON parser this repo uses; assert it matches directly.
            omitted_keys = list(expect["omitted"].keys())
            expected_order = [code for code in CANONICAL_OMISSION_ORDER if code in expect["omitted"]]
            self.assertEqual(omitted_keys, expected_order, f"{case_id}: omitted keys out of order")

    def _assert_header_matches_selected(self, case_id: str, store: dict, expect: dict) -> None:
        rows_by_id = {row["id"]: row for row in store["rows"]}
        pieces = []
        for selected_id in expect["selected"]:
            row = rows_by_id[selected_id]
            pieces.append(f"{row['name']}={row['value']}")
        self.assertEqual(expect["header"], "; ".join(pieces), f"{case_id}: header does not match selected")

    def _assert_canonical_token_list(self, tokens: list, context: str) -> None:
        self.assertIsInstance(tokens, list)
        seen_order = [token for token in CANONICAL_TOKEN_ORDER if token in tokens]
        self.assertEqual(
            tokens, seen_order, f"{context}: required tokens must be a subsequence in canonical order"
        )
        for token in tokens:
            self.assertIn(token, CANONICAL_TOKEN_ORDER, f"{context}: unknown token {token!r}")
        self.assertEqual(len(tokens), len(set(tokens)), f"{context}: duplicate token in required list")


class GeneratorDeterminismTests(unittest.TestCase):
    """Freshly generated stores must match the committed Node fixtures.

    Byte-identity is not the contract -- SQLite does not guarantee a stable
    on-disk layout for logically identical content. Row content, in
    declaration (`rowid`) order, is what both the generator and every
    consumer in later PRs actually read.
    """

    def test_fresh_build_matches_committed_node_fixtures(self) -> None:
        if not NODE_FIXTURES_DIR.exists():
            self.skipTest(f"{NODE_FIXTURES_DIR} does not exist; nothing to compare against")

        # Driven off the generator's own mapping rather than a hand-written
        # list: a store added to NODE_FIXTURE_STORES and forgotten here would
        # otherwise ship a fixture nothing ever compares.
        import build_isolation_corpus as build_module

        corpus = load_corpus()
        fixtures = {
            store_name: NODE_FIXTURES_DIR / filename
            for store_name, filename in build_module.NODE_FIXTURE_STORES.items()
        }
        self.assertGreater(len(fixtures), 0)
        if not all(fixture.exists() for fixture in fixtures.values()):
            self.skipTest(
                "committed Node isolation-corpus fixtures are absent; "
                "run with --write-node-fixtures"
            )

        tables = {"chromium": "cookies", "firefox": "moz_cookies"}
        with tempfile.TemporaryDirectory() as raw_out_dir:
            out_dir = Path(raw_out_dir)
            subprocess.run(
                [sys.executable, str(BUILD_SCRIPT), "--out-dir", str(out_dir)],
                check=True,
                cwd=ROOT,
            )
            for store_name, fixture in fixtures.items():
                table = tables[corpus["stores"][store_name]["engine"]]
                self._assert_same_content(
                    out_dir / f"{store_name}.sqlite", fixture, table
                )

    def test_committed_schema_matches_the_generator(self) -> None:
        """`schema.json` is generated, and the two Rust consumers assert their
        restated column lists against it. A stale committed copy would let
        them agree with each other and disagree with the generator."""
        import build_isolation_corpus as build_module

        committed = json.loads(build_module.SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            committed,
            build_module.schema_document(),
            "tests/isolation_corpus/schema.json is stale; regenerate it with "
            "`python3 build_isolation_corpus.py --out-dir <dir>` and commit the result",
        )

    def _assert_same_content(self, fresh_db: Path, fixture_base64: Path, table: str) -> None:
        fresh_rows = _select_all_rows(fresh_db, table)

        with tempfile.TemporaryDirectory() as decoded_dir:
            decoded_path = Path(decoded_dir) / fixture_base64.name.removesuffix(".base64")
            encoded = fixture_base64.read_text(encoding="ascii")
            decoded_path.write_bytes(base64.b64decode("".join(encoded.split())))
            fixture_rows = _select_all_rows(decoded_path, table)

        self.assertEqual(
            fresh_rows,
            fixture_rows,
            f"a fresh build of {table} no longer matches the committed Node fixture "
            f"({fixture_base64.name}); regenerate it with "
            "`python3 build_isolation_corpus.py --out-dir <dir> --write-node-fixtures` "
            "and commit the result",
        )


def _select_all_rows(database: Path, table: str) -> list[tuple]:
    connection = sqlite3.connect(str(database))
    try:
        return connection.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
    finally:
        connection.close()


class BuildScriptSmokeTests(unittest.TestCase):
    """The generator itself: schema shape and the CLI entry point."""

    def test_build_all_stores_produces_expected_schemas(self) -> None:
        sys.path.insert(0, str(ROOT))
        try:
            import build_isolation_corpus as build_module
        finally:
            sys.path.remove(str(ROOT))

        corpus = load_corpus()
        with tempfile.TemporaryDirectory() as raw_out_dir:
            out_dir = Path(raw_out_dir)
            paths = build_module.build_all_stores(corpus, out_dir)
            self.assertEqual(set(paths.keys()), set(corpus["stores"].keys()))

            connection = sqlite3.connect(str(paths["chromium_isolated"]))
            try:
                meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
                self.assertEqual(meta["version"], "24")
                self.assertEqual(meta["last_compatible_version"], "24")
                columns = {row[1] for row in connection.execute("PRAGMA table_info(cookies)")}
                self.assertTrue(
                    {
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
                    }.issubset(columns)
                )
                row_count = connection.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
                self.assertEqual(row_count, len(corpus["stores"]["chromium_isolated"]["rows"]))
                empty_encrypted = connection.execute(
                    "SELECT COUNT(*) FROM cookies WHERE encrypted_value != x''"
                ).fetchone()[0]
                self.assertEqual(empty_encrypted, 0, "encrypted_value must stay empty (plaintext value only)")
            finally:
                connection.close()

            connection = sqlite3.connect(str(paths["firefox_isolated"]))
            try:
                user_version = connection.execute("PRAGMA user_version").fetchone()[0]
                self.assertEqual(user_version, 16)
                columns = {row[1] for row in connection.execute("PRAGMA table_info(moz_cookies)")}
                self.assertTrue(
                    {
                        "host",
                        "name",
                        "value",
                        "path",
                        "isSecure",
                        "isHttpOnly",
                        "sameSite",
                        "expiry",
                        "originAttributes",
                    }.issubset(columns)
                )
                row_count = connection.execute("SELECT COUNT(*) FROM moz_cookies").fetchone()[0]
                self.assertEqual(row_count, len(corpus["stores"]["firefox_isolated"]["rows"]))
            finally:
                connection.close()

    def test_cli_writes_one_database_per_store(self) -> None:
        corpus = load_corpus()
        with tempfile.TemporaryDirectory() as raw_out_dir:
            out_dir = Path(raw_out_dir)
            subprocess.run(
                [sys.executable, str(BUILD_SCRIPT), "--out-dir", str(out_dir)],
                check=True,
                cwd=ROOT,
            )
            for store_name in corpus["stores"]:
                self.assertTrue((out_dir / f"{store_name}.sqlite").exists())

    def test_native_consumer_check_is_skipped_when_not_built(self) -> None:
        """Best-effort: open the generated stores with the CLI if it is
        already built on this machine; otherwise skip and say so rather than
        silently assuming success.

        This corpus is authored ahead of the Rust core (#331 PR 1/2) that
        will actually implement `send_view`/isolation matching, so on a
        fresh checkout there is usually nothing to check against yet.
        """
        # The `rookie-cookies-cli` package builds a binary named
        # `rookie-cookies` (`[[bin]] name` in `cli/Cargo.toml`), so globbing
        # for the package name found nothing even on a fully built checkout
        # and this check skipped unconditionally.
        cli_candidates = [
            candidate
            for pattern in ("*/rookie-cookies", "*/rookie-cookies.exe")
            for candidate in (REPO_ROOT / "target").glob(pattern)
            if candidate.is_file()
        ]
        if not cli_candidates:
            self.skipTest(
                "no built rookie-cookies binary found under target/; "
                "skipping the native-open check (build the CLI to enable it)"
            )
        cli = cli_candidates[0]
        corpus = load_corpus()
        with tempfile.TemporaryDirectory() as raw_out_dir:
            out_dir = Path(raw_out_dir)
            import build_isolation_corpus as build_module

            paths = build_module.build_all_stores(corpus, out_dir)
            chromium_db = paths["chromium_plain"]
            result = subprocess.run(
                [str(cli), "from-path", str(chromium_db), "--format", "json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                0,
                f"CLI could not open a freshly generated corpus store: {result.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
