"""Unit tests for crash-resistant native browser launch construction."""

from __future__ import annotations

import unittest
from pathlib import Path

import run_hosted_claimed_e2e as hosted
import webdriver_cookie as webdriver


class HostedBrowserRunnerTests(unittest.TestCase):
    def test_linux_chromium_uses_native_devtools_and_libsecret(self) -> None:
        command = hosted.chromium_native_command(
            "/opt/browser",
            Path("/tmp/profile"),
            "http://127.0.0.1:8765/set",
            platform="linux",
            has_xvfb=True,
            remote_debugging_port=9222,
        )
        self.assertEqual(command[:3], ["xvfb-run", "-a", "/opt/browser"])
        self.assertNotIn("--headless=new", command)
        self.assertIn("--password-store=gnome-libsecret", command)
        self.assertIn("--remote-debugging-port=9222", command)
        self.assertNotIn("--remote-debugging-pipe", command)

    def test_non_linux_chromium_needs_neither_xvfb_nor_libsecret(self) -> None:
        command = hosted.chromium_native_command(
            "/Applications/Browser",
            Path("/tmp/profile"),
            "http://127.0.0.1:8765/set",
            platform="darwin",
            has_xvfb=True,
            remote_debugging_port=9223,
        )
        self.assertEqual(command[0], "/Applications/Browser")
        self.assertNotIn("--password-store=gnome-libsecret", command)
        self.assertIn("--remote-debugging-port=9223", command)

    def test_windows_chromium_uses_native_headless_mode(self) -> None:
        command = hosted.chromium_native_command(
            r"C:\Browser\browser.exe",
            Path(r"C:\profile"),
            "http://127.0.0.1:8765/set",
            platform="win32",
            remote_debugging_port=9224,
        )
        self.assertIn("--headless=new", command)
        self.assertIn("--remote-debugging-port=9224", command)

    def test_ie_driver_command_is_platform_native(self) -> None:
        self.assertEqual(
            webdriver.driver_command("internet_explorer", "IEDriverServer.exe", 4444),
            ["IEDriverServer.exe", "--port=4444", "--log-level=TRACE"],
        )

    def test_safari_uses_normal_app_bundle(self) -> None:
        self.assertEqual(
            hosted.safari_open_command(
                "/Applications/Safari.app/Contents/MacOS/Safari",
                "http://127.0.0.1:8765/set",
            ),
            [
                "/usr/bin/open",
                "-b",
                "com.apple.Safari",
                "http://127.0.0.1:8765/set",
            ],
        )

    def test_ie_capabilities_pin_clean_native_session(self) -> None:
        edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        initial_url = "http://127.0.0.1:8765/set"
        options = webdriver.capabilities("internet_explorer", edge, initial_url)[
            "capabilities"
        ]["alwaysMatch"]
        self.assertEqual(options["browserName"], "internet explorer")
        self.assertTrue(options["se:ieOptions"]["ensureCleanSession"])
        self.assertTrue(options["se:ieOptions"]["ie.edgechromium"])
        self.assertEqual(options["se:ieOptions"]["ie.edgepath"], edge)
        self.assertEqual(options["se:ieOptions"]["initialBrowserUrl"], initial_url)


if __name__ == "__main__":
    unittest.main()
