from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run_with_ephemeral_keychain as subject


class EphemeralKeychainTests(unittest.TestCase):
    def test_disposable_keychain_is_first_then_original_list_is_restored(self) -> None:
        original = ["/Users/runner/Library/Keychains/login.keychain-db"]
        calls: list[tuple[str, ...]] = []

        def fake_security(*arguments: str, capture_output: bool = False):
            calls.append(arguments)
            stdout = "\n".join(f'    "{path}"' for path in original) if capture_output else ""
            return subprocess.CompletedProcess(arguments, 0, stdout, "")

        with tempfile.TemporaryDirectory() as runner_temp, mock.patch.object(
            subject.sys, "platform", "darwin"
        ), mock.patch.object(subject, "security", side_effect=fake_security), mock.patch(
            "run_with_ephemeral_keychain.subprocess.run",
            return_value=subprocess.CompletedProcess(["child"], 7),
        ), mock.patch.dict(subject.os.environ, {"RUNNER_TEMP": runner_temp}, clear=True):
            result = subject.run_isolated(
                ["child"],
                service="Chrome Safe Storage",
                accounts=["Chrome", "Chromium", "Chrome"],
            )

        self.assertEqual(result, 7)
        add_calls = [call for call in calls if call[:1] == ("add-generic-password",)]
        self.assertEqual(len(add_calls), 2)
        search_calls = [call for call in calls if call[:1] == ("list-keychains",)]
        self.assertEqual(search_calls[-1], ("list-keychains", "-d", "user", "-s", *original))
        temporary_search = search_calls[-2]
        self.assertEqual(temporary_search[-1], original[0])
        self.assertIn("rookie-e2e.keychain-db", Path(temporary_search[-2]).name)
        self.assertEqual(calls[-1][0], "delete-keychain")


if __name__ == "__main__":
    unittest.main()
