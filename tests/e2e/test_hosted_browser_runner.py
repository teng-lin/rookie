"""Unit tests for crash-resistant native browser launch construction."""

from __future__ import annotations

import unittest
from pathlib import Path

import run_hosted_claimed_e2e as hosted
import webdriver_cookie as webdriver


class HostedBrowserRunnerTests(unittest.TestCase):
    def test_linux_chromium_uses_native_headless_and_libsecret(self) -> None:
        command = hosted.chromium_native_command(
            "/opt/browser",
            Path("/tmp/profile"),
            "http://127.0.0.1:8765/set",
            platform="linux",
            has_xvfb=True,
        )
        self.assertEqual(command[:3], ["xvfb-run", "-a", "/opt/browser"])
        self.assertIn("--headless=new", command)
        self.assertIn("--password-store=gnome-libsecret", command)
        self.assertNotIn("--remote-debugging-pipe", command)

    def test_non_linux_chromium_needs_neither_xvfb_nor_libsecret(self) -> None:
        command = hosted.chromium_native_command(
            "/Applications/Browser",
            Path("/tmp/profile"),
            "http://127.0.0.1:8765/set",
            platform="darwin",
            has_xvfb=True,
        )
        self.assertEqual(command[0], "/Applications/Browser")
        self.assertNotIn("--password-store=gnome-libsecret", command)

    def test_vendor_driver_commands_are_platform_native(self) -> None:
        self.assertEqual(
            webdriver.driver_command("safari", "/usr/bin/safaridriver", 4444),
            ["/usr/bin/safaridriver", "--port", "4444"],
        )
        self.assertEqual(
            webdriver.driver_command("internet_explorer", "IEDriverServer.exe", 4444),
            ["IEDriverServer.exe", "--port=4444", "--log-level=TRACE"],
        )

    def test_ie_capabilities_pin_clean_native_session(self) -> None:
        options = webdriver.capabilities("internet_explorer")["capabilities"][
            "alwaysMatch"
        ]
        self.assertEqual(options["browserName"], "internet explorer")
        self.assertTrue(options["se:ieOptions"]["ensureCleanSession"])


if __name__ == "__main__":
    unittest.main()
