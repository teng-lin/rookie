"""Unit tests for the cross-platform CLI E2E assertion harness."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("assert_cli_cookie.py")
SPEC = importlib.util.spec_from_file_location("assert_cli_cookie", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class AssertCliCookieTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="rookie e2e ünicode ")
        root = Path(self.tempdir.name)
        self.cookies = root / "Firefox Profile" / "cookies.sqlite"
        self.cookies.parent.mkdir()
        self.cookies.touch()
        self.key = root / "Chromium Profile" / "Local State"
        self.key.parent.mkdir()
        self.key.touch()
        self.cli = root / ("rookie-cookies.exe" if sys.platform == "win32" else "rookie-cookies")
        self.cli.touch()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @mock.patch.object(HARNESS.subprocess, "run")
    def test_builds_chromium_command_and_accepts_seeded_cookie(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, json.dumps([{"name": "rookie_ci", "value": "bar"}]), "diagnostic"
        )

        count = HARNESS.assert_cli_cookie(
            self.cookies,
            key_path=self.key,
            domain="example.test",
            cli_path=self.cli,
        )

        self.assertEqual(count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(self.cli))
        self.assertEqual(command[command.index("--path") + 1], str(self.cookies))
        self.assertEqual(command[command.index("--key-path") + 1], str(self.key))
        self.assertEqual(command[command.index("--domains") + 1], "example.test")
        self.assertEqual(run.call_args.kwargs["env"]["RUST_LOG"], "error")

    @mock.patch.object(HARNESS.subprocess, "run")
    def test_firefox_command_omits_key_path(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, '[{"name":"rookie_ci","value":"bar"}]', ""
        )

        HARNESS.assert_cli_cookie(
            self.cookies,
            key_path=None,
            domain="127.0.0.1",
            cli_path=self.cli,
        )

        self.assertNotIn("--key-path", run.call_args.args[0])

    @mock.patch.object(HARNESS.subprocess, "run")
    def test_rejects_nonzero_exit_and_reports_stderr(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 7, "", "could not read database")

        with self.assertRaisesRegex(HARNESS.HarnessError, "status 7.*could not read"):
            HARNESS.assert_cli_cookie(
                self.cookies,
                key_path=None,
                domain="127.0.0.1",
                cli_path=self.cli,
            )

    @mock.patch.object(HARNESS.subprocess, "run")
    def test_rejects_invalid_json_or_missing_seeded_cookie(self, run: mock.Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, "not-json", "log line")
        with self.assertRaisesRegex(HARNESS.HarnessError, "not valid JSON"):
            HARNESS.assert_cli_cookie(
                self.cookies,
                key_path=None,
                domain="127.0.0.1",
                cli_path=self.cli,
            )

        run.return_value = subprocess.CompletedProcess(
            [], 0, '[{"name":"something_else","value":"bar"}]', ""
        )
        with self.assertRaisesRegex(HARNESS.HarnessError, "did not return rookie_ci=bar"):
            HARNESS.assert_cli_cookie(
                self.cookies,
                key_path=None,
                domain="127.0.0.1",
                cli_path=self.cli,
            )

    @mock.patch.object(HARNESS.subprocess, "run")
    def test_main_returns_failure_for_a_missing_database(self, run: mock.Mock) -> None:
        missing = self.cookies.with_name("missing.sqlite")
        with mock.patch.object(sys, "stderr") as stderr:
            status = HARNESS.main([str(missing), "--cli", str(self.cli)])

        self.assertEqual(status, 1)
        self.assertTrue(stderr.write.called)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
