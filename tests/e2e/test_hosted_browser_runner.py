"""Unit tests for crash-resistant native browser launch construction."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import run_hosted_claimed_e2e as hosted
import webdriver_cookie as webdriver


class HostedBrowserRunnerTests(unittest.TestCase):
    def test_seeded_legacy_chromium_db_wins_over_empty_network_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            user_data = Path(tmp)
            network = user_data / "Default/Network/Cookies"
            legacy = user_data / "Default/Cookies"
            for database in (network, legacy):
                database.parent.mkdir(parents=True, exist_ok=True)
                connection = hosted.sqlite3.connect(database)
                connection.execute("create table cookies (name text)")
                if database == legacy:
                    connection.execute("insert into cookies values ('rookie_ci')")
                connection.commit()
                connection.close()

            self.assertTrue(hosted.cookies_db_has_name(user_data))
            self.assertEqual(
                hosted.find_chromium_db(user_data, name="rookie_ci"), legacy
            )

    def test_profile_number_cookie_db_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            user_data = Path(tmp)
            database = user_data / "Profile 1/Network/Cookies"
            database.parent.mkdir(parents=True)
            connection = hosted.sqlite3.connect(database)
            connection.execute("create table cookies (name text)")
            connection.execute("insert into cookies values ('rookie_ci')")
            connection.commit()
            connection.close()

            self.assertEqual(
                hosted.find_chromium_db(user_data, name="rookie_ci"), database
            )

    def test_windows_yandex_uses_its_native_profile_root(self) -> None:
        with mock.patch.dict(hosted.os.environ, {"LOCALAPPDATA": r"C:\Users\runner"}):
            actual = hosted.native_chromium_user_data(
                "yandex", Path(r"D:\temp\custom"), platform="win32"
            )
        self.assertEqual(
            actual,
            Path(r"C:\Users\runner") / "Yandex/YandexBrowser/User Data",
        )

    def test_wininet_cookie_seed_is_persistent_and_gmt(self) -> None:
        seeded = hosted.wininet_cookie_data(
            datetime(2026, 8, 21, 12, 30, 0, tzinfo=timezone.utc)
        )
        self.assertEqual(
            seeded,
            "bar; expires=Fri, 21-Aug-2026 13:30:00 GMT; path=/",
        )

    def test_persisted_cookie_can_replace_unreachable_devtools_endpoint(self) -> None:
        proc = mock.Mock()
        with (
            mock.patch.object(hosted, "urlopen", side_effect=OSError),
            mock.patch.object(hosted, "cookies_db_has_name", return_value=True),
        ):
            has_devtools = hosted.wait_for_devtools_or_cookie(
                proc, 9222, Path("/tmp/profile")
            )
        self.assertFalse(has_devtools)

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
        self.assertEqual(command[-1], "http://127.0.0.1:8765/set")

    def test_linux_edge_uses_headless_mode_to_bypass_first_run_ui(self) -> None:
        command = hosted.chromium_native_command(
            "/usr/bin/microsoft-edge",
            Path("/tmp/profile"),
            "http://127.0.0.1:8765/set",
            platform="linux",
            has_xvfb=True,
            remote_debugging_port=9222,
        )
        self.assertIn("--headless=new", command)

    def test_ie_snapshot_uses_windows_esent_copy_mode(self) -> None:
        source = Path(r"C:\WebCache\WebCacheV01.dat")
        destination = Path(r"D:\temp\rookie-ie.dat")
        self.assertEqual(
            hosted.esent_copy_command(source, destination),
            [
                "esentutl.exe",
                "/y",
                str(source),
                f"/d{destination}",
                "/o",
            ],
        )
        self.assertEqual(
            hosted.esent_recovery_command(destination.parent),
            [
                "esentutl.exe",
                "/r",
                "V01",
                f"/l{destination.parent}",
                f"/s{destination.parent}",
                f"/d{destination.parent}",
                "/o",
            ],
        )
        self.assertEqual(
            hosted.webcache_host_commands([4321, 1234, 4321, -1]),
            [
                ["taskkill", "/F", "/PID", "1234"],
                ["taskkill", "/F", "/PID", "4321"],
            ],
        )

    def test_ie_null_new_session_value_is_a_webdriver_error(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 1
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(webdriver, "free_port", return_value=4444),
            mock.patch.object(webdriver.subprocess, "Popen", return_value=proc),
            mock.patch.object(webdriver, "wait_for_driver"),
            mock.patch.object(webdriver, "capabilities", return_value={}),
            mock.patch.object(webdriver, "request_json", return_value={"value": None}),
        ):
            with self.assertRaisesRegex(
                webdriver.WebDriverError, "did not return a session id"
            ):
                webdriver.seed_once(
                    "internet_explorer",
                    "IEDriverServer.exe",
                    "http://127.0.0.1/set",
                    Path(tmp) / "driver.log",
                    {},
                )

    def test_ie_cookie_store_timeout_is_not_reported_as_query_failure(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 1
        responses = [
            {"value": {"sessionId": "session"}},
            {"value": {"name": "rookie_ci", "value": "bar"}},
        ]
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(webdriver, "free_port", return_value=4444),
            mock.patch.object(webdriver.subprocess, "Popen", return_value=proc),
            mock.patch.object(webdriver, "wait_for_driver"),
            mock.patch.object(webdriver, "capabilities", return_value={}),
            mock.patch.object(webdriver, "request_json", side_effect=responses),
            mock.patch.object(
                webdriver,
                "wait_for_changed_cookie_file",
                side_effect=webdriver.WebDriverError("cookie store did not update"),
            ),
        ):
            with self.assertRaisesRegex(
                webdriver.WebDriverError, "cookie store did not update"
            ):
                webdriver.seed_once(
                    "internet_explorer",
                    "IEDriverServer.exe",
                    "http://127.0.0.1/set",
                    Path(tmp) / "driver.log",
                    {},
                )

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
        self.assertIn("--use-mock-keychain", command)
        self.assertIn("--remote-debugging-port=9223", command)
        self.assertEqual(command[-1], "http://127.0.0.1:8765/set")

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
        self.assertEqual(command[-1], "http://127.0.0.1:8765/set")

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

    def test_safari_store_access_checks_the_binarycookies_signature(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cookie_file = Path(tmp) / "Cookies.binarycookies"
            cookie_file.write_bytes(b"cookfixture")
            hosted.verify_safari_store_access(cookie_file)

    def test_safari_tcc_denial_is_not_suppressed_as_an_absent_store(self) -> None:
        path = mock.Mock(spec=Path)
        path.stat.side_effect = PermissionError("operation not permitted")
        with (
            mock.patch.object(webdriver, "candidate_cookie_files", return_value=[path]),
            self.assertRaisesRegex(webdriver.WebDriverError, "Full Disk Access"),
        ):
            webdriver.file_snapshot("safari")

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
