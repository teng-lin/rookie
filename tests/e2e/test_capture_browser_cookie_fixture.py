"""Safety and provenance tests for browser-generated fixture capture."""

from __future__ import annotations

import importlib.util
import json
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


CAPTURE = load_module(
    "capture_browser_cookie_fixture", "capture_browser_cookie_fixture.py"
)


class CaptureBrowserCookieFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookie capture test ")
        self.root = Path(self.tempdir.name)
        self.source_root = self.root / "disposable-profile"
        self.source_root.mkdir()
        (self.source_root / CAPTURE.MARKER_NAME).write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": CAPTURE.MARKER_KIND,
                    "source_kind": "unit_test",
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_manifest(
        self, engine: str, cookies: list[dict[str, object]]
    ) -> Path:
        manifest = self.root / f"{engine}-expected.json"
        manifest.write_text(
            json.dumps({"schema_version": 1, "engine": engine, "cookies": cookies}),
            encoding="utf-8",
        )
        return manifest

    def run_capture(self, engine: str, database: Path, manifest: Path) -> tuple[Path, Path]:
        output = self.root / f"{engine}-fixture.sqlite"
        provenance = self.root / f"{engine}-fixture.provenance.json"
        status = CAPTURE.main(
            [
                "--source-root",
                str(self.source_root),
                "--source-database",
                str(database),
                "--output-database",
                str(output),
                "--expected-manifest",
                str(manifest),
                "--provenance-output",
                str(provenance),
                "--engine",
                engine,
                "--browser",
                "Disposable Browser",
                "--browser-version",
                "123.4",
                "--build-id",
                "unit-build",
                "--platform",
                "unit-os",
                "--architecture",
                "unit-arch",
            ]
        )
        self.assertEqual(status, 0)
        return output, provenance

    def test_chromium_capture_keeps_only_manifest_rows_and_safe_meta(self) -> None:
        database = self.source_root / "Default" / "Network" / "Cookies"
        database.parent.mkdir(parents=True)
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                """
                CREATE TABLE meta (key TEXT NOT NULL, value TEXT NOT NULL);
                INSERT INTO meta VALUES ('version', '24');
                INSERT INTO meta VALUES ('compatible_version', '24');
                INSERT INTO meta VALUES ('private_source_path', '/Users/example');
                CREATE TABLE cookies (
                  host_key TEXT NOT NULL, path TEXT NOT NULL, name TEXT NOT NULL,
                  value TEXT NOT NULL, encrypted_value BLOB NOT NULL,
                  top_frame_site_key TEXT NOT NULL,
                  has_cross_site_ancestor INTEGER NOT NULL
                );
                CREATE TABLE telemetry (secret TEXT NOT NULL);
                INSERT INTO telemetry VALUES ('must-not-survive');
                """
            )
            connection.executemany(
                "INSERT INTO cookies VALUES (?, ?, ?, '', ?, ?, ?)",
                [
                    (".example.test", "/", "kept", b"v10synthetic", "", 0),
                    ("private.test", "/", "kept", b"v10same-name", "", 0),
                    ("private.test", "/", "decoy", b"v10private", "", 0),
                ],
            )
            connection.commit()
        finally:
            connection.close()

        manifest = self.write_manifest(
            "chromium",
            [
                {
                    "cookie": {
                        "domain": ".example.test",
                        "path": "/",
                        "name": "kept",
                        "value": "synthetic",
                    },
                    "context": {},
                }
            ],
        )
        output, provenance_path = self.run_capture("chromium", database, manifest)

        connection = sqlite3.connect(output)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT host_key, path, name FROM cookies"
                ).fetchall(),
                [(".example.test", "/", "kept")],
            )
            self.assertEqual(connection.execute("SELECT * FROM telemetry").fetchall(), [])
            self.assertEqual(
                connection.execute("SELECT key FROM meta ORDER BY key").fetchall(),
                [("compatible_version",), ("version",)],
            )
        finally:
            connection.close()
        self.assertNotIn(b"must-not-survive", output.read_bytes())
        self.assertNotIn(b"private_source_path", output.read_bytes())
        self.assertNotIn(b"private.test", output.read_bytes())

        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        self.assertEqual(provenance["retained_cookie_rows"], 1)
        self.assertEqual(provenance["source_cookie_rows"], 3)
        self.assertEqual(provenance["schema"]["meta"]["version"], "24")
        self.assertEqual(len(provenance["fixture_sha256"]), 64)

    def test_firefox_capture_preserves_origin_attributes_identity(self) -> None:
        database = self.source_root / "cookies.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(
                """
                CREATE TABLE moz_cookies (
                  id INTEGER PRIMARY KEY, host TEXT NOT NULL, path TEXT NOT NULL,
                  name TEXT NOT NULL, value TEXT NOT NULL,
                  originAttributes TEXT NOT NULL
                );
                INSERT INTO moz_cookies VALUES
                  (1, '.example.test', '/', 'kept', 'synthetic',
                   '^partitionKey=%28https%2Ctop.example%29');
                INSERT INTO moz_cookies VALUES
                  (2, 'private.test', '/', 'decoy', 'private-value', '');
                """
            )
            connection.commit()
        finally:
            connection.close()

        manifest = self.write_manifest(
            "firefox",
            [
                {
                    "cookie": {
                        "domain": ".example.test",
                        "path": "/",
                        "name": "kept",
                        "value": "synthetic",
                    },
                    "context": {
                        "origin_attributes": "^partitionKey=%28https%2Ctop.example%29"
                    },
                }
            ],
        )
        output, provenance_path = self.run_capture("firefox", database, manifest)
        connection = sqlite3.connect(output)
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT host, path, name, value, originAttributes FROM moz_cookies"
                ).fetchall(),
                [
                    (
                        ".example.test",
                        "/",
                        "kept",
                        "synthetic",
                        "^partitionKey=%28https%2Ctop.example%29",
                    )
                ],
            )
        finally:
            connection.close()
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        self.assertEqual(provenance["engine"], "firefox")
        self.assertEqual(provenance["source_kind"], "unit_test")

    def test_unmarked_source_is_refused(self) -> None:
        (self.source_root / CAPTURE.MARKER_NAME).unlink()
        database = self.source_root / "cookies.sqlite"
        database.touch()
        with self.assertRaisesRegex(CAPTURE.CaptureError, "refusing unmarked"):
            CAPTURE.require_disposable_source(self.source_root, database)

    def test_source_database_must_be_inside_marked_root(self) -> None:
        database = self.root / "outside.sqlite"
        database.touch()
        with self.assertRaisesRegex(CAPTURE.CaptureError, "inside --source-root"):
            CAPTURE.require_disposable_source(self.source_root, database)

    def test_manifest_mismatch_leaves_no_output(self) -> None:
        database = self.source_root / "cookies.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE moz_cookies "
                "(host TEXT, path TEXT, name TEXT, value TEXT, originAttributes TEXT)"
            )
            connection.execute(
                "INSERT INTO moz_cookies VALUES ('.example.test', '/', 'actual', 'x', '')"
            )
            connection.commit()
        finally:
            connection.close()
        manifest = self.write_manifest(
            "firefox",
            [{"domain": ".example.test", "path": "/", "name": "missing"}],
        )
        output = self.root / "bad.sqlite"
        expected, _ = CAPTURE.load_expected_rows(manifest, "firefox")
        with self.assertRaisesRegex(CAPTURE.CaptureError, "do not exactly match"):
            CAPTURE.sanitize_database(database, output, "firefox", expected)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
