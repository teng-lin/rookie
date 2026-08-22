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
    def test_legacy_ie_runner_requires_the_exact_single_cookie_set(self) -> None:
        environment: dict[str, str] = {}
        hosted.require_exact_single_cookie(environment)
        self.assertEqual(
            environment["ROOKIE_E2E_REQUIRED_COOKIES_JSON"],
            '{"rookie_ci": "bar"}',
        )
        self.assertEqual(environment["ROOKIE_E2E_FORBIDDEN_COOKIES_JSON"], "[]")
        self.assertEqual(environment["ROOKIE_E2E_EXACT_COOKIE_STATE"], "1")

    def test_isolated_discovery_environment_stays_below_sandbox(self) -> None:
        sandbox = Path("/tmp/rookie-registry-sandbox")
        environment = hosted.isolated_discovery_environment(sandbox)
        self.assertTrue(
            all(Path(value).is_relative_to(sandbox) for value in environment.values())
        )

    def test_registry_root_template_resolves_only_isolated_placeholders(self) -> None:
        environment = hosted.isolated_discovery_environment(Path("/tmp/sandbox"))
        resolved = hosted.resolve_fixture_root(
            "{local_app_data}/Packages/Browser_*/User Data", environment
        )
        self.assertEqual(
            resolved,
            Path(
                "/tmp/sandbox/home/AppData/Local/Packages/Browser_rookie-fixture/User Data"
            ),
        )

    def test_gecko_discovery_profile_has_a_profiles_ini(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                hosted,
                "registry_browser",
                return_value={
                    "roots": [
                        {
                            "template": "{home}/.fixture-browser",
                            "priority": 10,
                        }
                    ]
                },
            ):
                profile, environment = hosted.prepare_discovered_profile(
                    Path(tmp), "linux", "fixture", "gecko"
                )

            self.assertEqual(
                profile,
                Path(environment["HOME"]) / ".fixture-browser/Profiles/rookie-e2e",
            )
            profiles_ini = profile.parents[1] / "profiles.ini"
            self.assertIn("Path=Profiles/rookie-e2e", profiles_ini.read_text())

    def test_hosted_profile_id_is_independent_and_registry_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            root = {
                "template": "{home}/.fixture-browser",
                "priority": 10,
                "root_id": "fixture-root",
                "channel": "stable",
            }
            with mock.patch.object(
                hosted, "registry_browser", return_value={"roots": [root]}
            ):
                profile, environment = hosted.prepare_discovered_profile(
                    sandbox, "linux", "fixture", "chromium"
                )
                profile_id = hosted.independently_expected_profile_id(
                    "linux", "fixture", "chromium", profile, environment
                )
            self.assertEqual(len(profile_id), 64)
            self.assertTrue(
                all(character in "0123456789abcdef" for character in profile_id)
            )

    def test_windows_profile_id_hash_uses_rust_verbatim_canonical_path(self) -> None:
        root = Path(r"D:\a\_temp\rookie\User Data")
        self.assertEqual(
            str(hosted.canonical_root_digest_path(root, "windows")),
            r"\\?\D:\a\_temp\rookie\User Data",
        )
        self.assertEqual(hosted.canonical_root_digest_path(root, "macos"), root)

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

    def test_gecko_waits_for_full_corpus_then_closes_before_extraction(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile"
            request_log = Path(temporary) / "requests.log"
            with (
                mock.patch.object(
                    hosted.subprocess, "Popen", return_value=proc
                ) as popen,
                mock.patch.object(hosted, "wait_for_request") as wait_for_request,
                mock.patch.object(
                    hosted, "wait_for_gecko_database"
                ) as wait_for_database,
            ):
                hosted.seed_gecko(
                    "/opt/librewolf",
                    profile,
                    "http://127.0.0.1/corpus/run?engine=firefox&step=0",
                    request_log,
                )

        self.assertEqual(popen.call_args.args[0][0], "/opt/librewolf")
        self.assertNotIn("xvfb-run", popen.call_args.args[0])
        wait_for_request.assert_called_once_with(
            request_log, "/corpus/run", timeout=90, query_contains="step=3"
        )
        proc.terminate.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=15)
        wait_for_database.assert_called_once_with(profile)

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

    def test_devtools_wait_fails_immediately_after_launcher_error(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 23
        with (
            mock.patch.object(hosted, "urlopen", side_effect=OSError),
            mock.patch.object(hosted, "cookies_db_has_name", return_value=False),
            mock.patch.object(hosted.time, "sleep") as sleep,
            self.assertRaisesRegex(SystemExit, "exited 23"),
        ):
            hosted.wait_for_devtools_or_cookie(
                proc, 9222, Path("/tmp/profile"), timeout=60
            )

        sleep.assert_not_called()

    def test_chromium_cookie_checkpoint_is_retried_after_launcher_exit(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 0
        profile = Path("/tmp/profile")
        with (
            mock.patch.object(hosted.subprocess, "Popen", return_value=proc),
            mock.patch.object(hosted, "pick_devtools_port", return_value=9222),
            mock.patch.object(hosted, "wait_for_devtools_or_cookie", return_value=True),
            mock.patch.object(hosted, "navigate_chromium_cdp"),
            mock.patch.object(
                hosted, "wait_for_chromium_cookie", side_effect=[False, True]
            ) as wait_for_cookie,
        ):
            hosted.seed_chromium_native(
                r"C:\Browser\browser.exe",
                profile,
                "http://127.0.0.1:8765/set",
            )

        self.assertEqual(
            wait_for_cookie.call_args_list,
            [
                mock.call(profile, 30, name="rookie_ci"),
                mock.call(profile, 15, name="rookie_ci"),
            ],
        )

    def test_chromium_corpus_waits_for_final_decoy_checkpoint(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 0
        profile = Path("/tmp/profile")
        with (
            mock.patch.object(hosted.subprocess, "Popen", return_value=proc),
            mock.patch.object(hosted, "pick_devtools_port", return_value=9222),
            mock.patch.object(hosted, "wait_for_devtools_or_cookie", return_value=True),
            mock.patch.object(hosted, "navigate_chromium_cdp"),
            mock.patch.object(
                hosted, "wait_for_chromium_cookie", return_value=True
            ) as wait_for_cookie,
            mock.patch.object(hosted.time, "sleep"),
        ):
            hosted.seed_chromium_native(
                "/opt/browser",
                profile,
                "http://127.0.0.1:8765/corpus/run?engine=chromium&step=0",
            )

        wait_for_cookie.assert_called_once_with(profile, 30, name="rookie_decoy")

    def test_chromium_cleanup_kills_launcher_that_ignores_terminate(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = hosted.subprocess.TimeoutExpired("browser", 10)
        with (
            mock.patch.object(hosted.subprocess, "Popen", return_value=proc),
            mock.patch.object(hosted, "pick_devtools_port", return_value=9222),
            mock.patch.object(
                hosted, "wait_for_devtools_or_cookie", return_value=False
            ),
            mock.patch.object(hosted, "wait_for_chromium_cookie", return_value=True),
            mock.patch.object(hosted.time, "sleep"),
        ):
            hosted.seed_chromium_native(
                "/opt/browser", Path("/tmp/profile"), "http://127.0.0.1:8765/set"
            )

        proc.terminate.assert_called_once_with()
        proc.wait.assert_called_once_with(timeout=10)
        proc.kill.assert_called_once_with()

    def test_chromium_cookie_retry_exhaustion_reports_candidates(self) -> None:
        proc = mock.Mock()
        proc.poll.return_value = 0
        profile = Path("/tmp/profile")
        with (
            mock.patch.object(hosted.subprocess, "Popen", return_value=proc),
            mock.patch.object(hosted, "pick_devtools_port", return_value=9222),
            mock.patch.object(
                hosted, "wait_for_devtools_or_cookie", return_value=False
            ),
            mock.patch.object(
                hosted, "wait_for_chromium_cookie", side_effect=[False, False]
            ),
            mock.patch.object(hosted, "chromium_cookie_dbs", return_value=[]),
            self.assertRaisesRegex(SystemExit, "cookie databases: <none>"),
        ):
            hosted.seed_chromium_native(
                "/opt/browser", profile, "http://127.0.0.1:8765/set"
            )

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

    def test_linux_edge_gets_extended_startup_budget(self) -> None:
        self.assertEqual(
            hosted.chromium_startup_timeout(
                "/usr/bin/microsoft-edge", platform="linux"
            ),
            90,
        )
        self.assertEqual(
            hosted.chromium_startup_timeout("/usr/bin/chromium", platform="linux"),
            45,
        )

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

    def test_safari_live_run_refuses_a_local_default_profile(self) -> None:
        with (
            mock.patch.dict(hosted.os.environ, {}, clear=True),
            self.assertRaisesRegex(SystemExit, "fresh GitHub-hosted CI account"),
        ):
            hosted.require_disposable_safari_host(Path("/tmp/safari"))

    def test_safari_live_run_requires_scratch_below_runner_temp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            scratch = runner_temp / "rookie-ci/safari"
            with mock.patch.dict(
                hosted.os.environ,
                {
                    "CI": "true",
                    "GITHUB_ACTIONS": "true",
                    "RUNNER_TEMP": str(runner_temp),
                },
                clear=False,
            ):
                hosted.require_disposable_safari_host(scratch)
                with self.assertRaisesRegex(SystemExit, "outside RUNNER_TEMP"):
                    hosted.require_disposable_safari_host(
                        Path("/tmp/not-runner/safari")
                    )

    def test_safari_https_certificate_is_installed_in_disposable_keychain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary) / "safari"
            keychain = Path(temporary) / "rookie-e2e.keychain-db"
            with (
                mock.patch.object(hosted.sys, "platform", "darwin"),
                mock.patch.dict(
                    hosted.os.environ,
                    {"ROOKIE_E2E_EPHEMERAL_KEYCHAIN": str(keychain)},
                ),
                mock.patch.object(hosted.shutil, "which", return_value="/opt/openssl"),
                mock.patch.object(hosted.subprocess, "run") as run,
            ):
                certificate, private_key = hosted.generate_trusted_safari_certificate(
                    scratch
                )
                extensions = (scratch / "tls/rookie-localhost.ext").read_text()

        self.assertEqual(certificate, scratch / "tls/rookie-localhost.pem")
        self.assertEqual(private_key, scratch / "tls/rookie-localhost-key.pem")
        openssl_command = run.call_args_list[0].args[0]
        self.assertEqual(openssl_command[0:3], ["/opt/openssl", "req", "-x509"])
        sign_command = run.call_args_list[2].args[0]
        self.assertEqual(sign_command[0:3], ["/opt/openssl", "x509", "-req"])
        self.assertIn("subjectAltName=IP:127.0.0.1,DNS:localhost", extensions)
        trust_command = run.call_args_list[3].args[0]
        self.assertEqual(
            trust_command[0:3], ["/usr/bin/security", "add-trusted-cert", "-r"]
        )
        self.assertEqual(trust_command[trust_command.index("-k") + 1], str(keychain))
        self.assertEqual(trust_command[-1], str(scratch / "tls/rookie-local-ca.pem"))

    def test_safari_https_refuses_a_normal_keychain(self) -> None:
        with (
            mock.patch.object(hosted.sys, "platform", "darwin"),
            mock.patch.dict(hosted.os.environ, {}, clear=True),
            self.assertRaisesRegex(SystemExit, "disposable Keychain"),
        ):
            hosted.generate_trusted_safari_certificate(Path("/tmp/safari"))

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
