"""Synthetic checks for the live Firefox-container E2E oracle."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sqlite3
import tempfile
import unittest
from unittest import mock

from run_active_writer_e2e import ActiveWriterError
from run_firefox_container_e2e import (
    container_cookie_present,
    container_seed_ready,
    posix_process_group_exists,
    stop_windows_process_tree,
    stop_web_ext,
    wait_for_posix_process_group_exit,
    write_container_manifest,
)


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

    def test_container_seed_ready_requires_the_post_cookie_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            containers = Path(temporary) / "containers.json"
            self.assertFalse(container_seed_ready(containers))
            containers.write_text(
                json.dumps(
                    {
                        "identities": [
                            {
                                "name": "rookie-e2e-container",
                                "userContextId": 7,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertFalse(container_seed_ready(containers))
            containers.write_text(
                json.dumps(
                    {
                        "identities": [
                            {
                                "name": "rookie-e2e-container-ready",
                                "userContextId": 7,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(container_seed_ready(containers))

    @unittest.skipIf(os.name == "nt", "POSIX process-group behavior")
    def test_stop_web_ext_terminates_the_firefox_process_group(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.pid = 1234
        with (
            mock.patch("run_firefox_container_e2e.os.killpg") as killpg,
            mock.patch(
                "run_firefox_container_e2e.wait_for_posix_process_group_exit",
                return_value=True,
            ) as wait_for_group,
        ):
            stop_web_ext(process)
        killpg.assert_called_once_with(1234, signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=15)
        wait_for_group.assert_called_once_with(1234, 15)

    def test_wait_for_posix_process_group_exit_observes_every_member(self) -> None:
        with (
            mock.patch(
                "run_firefox_container_e2e.posix_process_group_exists",
                side_effect=[True, False],
            ),
            mock.patch("run_firefox_container_e2e.time.sleep"),
        ):
            self.assertTrue(wait_for_posix_process_group_exit(1234, 5))

    def test_unsignalable_posix_group_has_no_owned_members(self) -> None:
        with mock.patch(
            "run_firefox_container_e2e.os.killpg", side_effect=PermissionError
        ):
            self.assertFalse(posix_process_group_exists(1234))

    def test_stop_windows_process_tree_includes_firefox_descendants(self) -> None:
        process = mock.Mock()
        process.poll.return_value = None
        process.pid = 1234
        with mock.patch("run_firefox_container_e2e.subprocess.run") as run:
            stop_windows_process_tree(process)
        run.assert_called_once_with(
            ["taskkill", "/PID", "1234", "/T"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        process.wait.assert_called_once_with(timeout=15)

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
