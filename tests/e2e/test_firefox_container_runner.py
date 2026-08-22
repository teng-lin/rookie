"""Synthetic checks for the live Firefox-container E2E oracle."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from run_active_writer_e2e import ActiveWriterError
from run_firefox_container_e2e import container_cookie_present, write_container_manifest


class FirefoxContainerRunnerTests(unittest.TestCase):
    def database(self, root: Path, origin_attributes: str) -> Path:
        database = root / "cookies.sqlite"
        connection = sqlite3.connect(database)
        connection.execute(
            "create table moz_cookies (host text, path text, isSecure integer, "
            "expiry integer, name text, value text, isHttpOnly integer, "
            "sameSite integer, originAttributes text)"
        )
        connection.execute(
            "insert into moz_cookies values "
            "('container.rookie.test', '/', 1, 4102444800, "
            "'rookie_container', 'container-1', 1, 1, ?)",
            (origin_attributes,),
        )
        connection.commit()
        connection.close()
        return database

    def test_container_cookie_presence_handles_missing_and_committed_stores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "cookies.sqlite"
            self.assertFalse(container_cookie_present(database))
            database = self.database(root, "^userContextId=7")
            self.assertTrue(container_cookie_present(database))

    def test_raw_container_manifest_preserves_the_complete_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = self.database(root, "^userContextId=7")
            output = root / "manifest.json"
            self.assertEqual(write_container_manifest(database, output), 7)
            document = json.loads(output.read_text(encoding="utf-8"))
            record = document["expected"]["detailed"][0]
            self.assertEqual(record["context"]["origin_attributes"], "^userContextId=7")
            self.assertEqual(record["context"]["user_context_id"], 7)
            self.assertEqual(record["cookie"]["value"], "container-1")

    def test_raw_container_manifest_rejects_partition_or_private_identity(self) -> None:
        for attributes in (
            "^userContextId=7&partitionKey=%28https%2Cexample.test%29",
            "^userContextId=7&privateBrowsingId=1",
            "^userContextId=0",
        ):
            with self.subTest(attributes=attributes), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                database = self.database(root, attributes)
                with self.assertRaisesRegex(ActiveWriterError, "isolation attributes"):
                    write_container_manifest(database, root / "manifest.json")


if __name__ == "__main__":
    unittest.main()
