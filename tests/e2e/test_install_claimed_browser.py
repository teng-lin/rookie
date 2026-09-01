"""The silent-install catalog must stay 1:1 with nightly hosted extra browsers."""

from __future__ import annotations

import ast
import glob
import importlib.util
import inspect
import io
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_browser_coverage as coverage


MODULE_PATH = Path(__file__).with_name("install_claimed_browser.py")
SPEC = importlib.util.spec_from_file_location("install_claimed_browser", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)

# Read the branches install_spec() dispatches on straight out of its source so
# this stays in step with the installer. A catalog entry naming a kind the
# dispatch does not know fails to install and only surfaces as a red nightly
# cell.
def install_kinds() -> frozenset[str]:
    tree = ast.parse(inspect.getsource(INSTALL.install_spec))
    kinds = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for comparator in node.comparators:
            operands = (
                comparator.elts
                if isinstance(comparator, ast.Tuple)
                else [comparator]
            )
            kinds.update(
                operand.value
                for operand in operands
                if isinstance(operand, ast.Constant)
                and isinstance(operand.value, str)
            )
    return frozenset(kinds)


INSTALL_KINDS = install_kinds()

# Seeded by e2e.yml without this installer. The claimed-browser workflow now
# owns every other real-browser cell, including Playwright-distributed
# Chromium, image/Playwright Edge, and normal-profile Safari.
PREINSTALLED = frozenset(
    {
        ("linux", "chrome"),
        ("linux", "firefox"),
        ("macos", "chrome"),
        ("macos", "firefox"),
        ("windows", "chrome"),
        ("windows", "firefox"),
    }
)


class InstallCatalogTests(unittest.TestCase):
    def test_every_catalog_cell_is_nightly_hosted(self) -> None:
        catalog = {(row["platform"], row["browser"]) for row in INSTALL.matrix()}
        extra = coverage.NIGHTLY_HOSTED - PREINSTALLED
        self.assertEqual(catalog, extra)

    def test_windows_brave_includes_per_user_localappdata(self) -> None:
        exe = INSTALL.HOSTS["brave"]["windows"]["exe"]
        self.assertTrue(
            any("LocalAppData" in path and "brave.exe" in path for path in exe)
        )

    def test_opera_gx_macos_lists_opera_binary(self) -> None:
        exe = INSTALL.HOSTS["opera_gx"]["macos"]["exe"]
        self.assertTrue(any(path.endswith("/Opera") for path in exe))

    def test_native_engine_cells_use_vendor_drivers(self) -> None:
        safari = INSTALL.HOSTS["safari"]["macos"]
        internet_explorer = INSTALL.HOSTS["internet_explorer"]["windows"]
        self.assertEqual(safari["kind"], "system_browser")
        self.assertIn("/Applications/Safari.app/Contents/MacOS/Safari", safari["exe"])
        self.assertEqual(internet_explorer["kind"], "internet_explorer")
        self.assertFalse(INSTALL.HOSTS["internet_explorer"]["hosted"])
        self.assertEqual(internet_explorer["runner"], "windows-2022")
        self.assertIn("iedriver-win32", internet_explorer["exe"][0])
        self.assertTrue(
            any(
                path.endswith("IEDriverServer.exe") for path in internet_explorer["exe"]
            )
        )
        self.assertTrue(
            any(path.endswith("msedge.exe") for path in internet_explorer["edge_exe"])
        )

    def test_chromium_and_edge_have_official_playwright_install_fallbacks(self) -> None:
        for platform in INSTALL.RUNNERS:
            self.assertEqual(
                INSTALL.HOSTS["chromium"][platform]["kind"],
                "playwright_browser",
            )
            self.assertEqual(
                INSTALL.HOSTS["edge"][platform]["kind"],
                "playwright_channel",
            )

    def test_playwright_installer_uses_resolved_npx_shim(self) -> None:
        npx = r"C:\Program Files\nodejs\npx.CMD"
        with (
            mock.patch.object(INSTALL.shutil, "which", return_value=npx),
            mock.patch.object(INSTALL, "run") as run,
        ):
            INSTALL.install_playwright_product("chromium")
        run.assert_called_once_with(
            [npx, "playwright", "install", "chromium"],
            cwd=INSTALL.ROOT / "tests/e2e",
        )

    def test_winget_installer_does_not_query_the_region_gated_store(self) -> None:
        completed = INSTALL.subprocess.CompletedProcess([], 0)
        with mock.patch.object(
            INSTALL.subprocess, "run", return_value=completed
        ) as run:
            INSTALL.install_winget("Yandex.Browser")

        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--source") + 1], "winget")
        self.assertIn("--accept-source-agreements", command)

    def test_find_exe_resolves_globs_and_app_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app_macos = root / "Opera GX.app" / "Contents" / "MacOS"
            app_macos.mkdir(parents=True)
            binary = app_macos / "Opera"
            binary.write_bytes(b"fake-browser\n")
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            found = INSTALL.find_exe(
                [
                    str(app_macos / "Opera GX"),
                    str(root / "*.app" / "Contents" / "MacOS" / "Opera"),
                ]
            )
            self.assertEqual(Path(found).resolve(), binary.resolve())

    def test_find_exe_expands_recursive_globs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "Packages" / "DuckDuckGo.DesktopBrowser_1" / "Local"
            nested.mkdir(parents=True)
            exe = nested / "DuckDuckGo.exe"
            exe.write_bytes(b"fake-browser\n")
            found = INSTALL.find_exe(
                [str(root / "Packages" / "DuckDuckGo*" / "**" / "DuckDuckGo.exe")]
            )
            self.assertEqual(Path(found).resolve(), exe.resolve())

    def test_is_launchable_rejects_empty_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "Arc.exe"
            empty.write_bytes(b"")
            self.assertFalse(INSTALL.is_launchable(empty))
            real = Path(tmp) / "brave.exe"
            real.write_bytes(b"fake-browser\n")
            self.assertTrue(INSTALL.is_launchable(real))

    def test_catalog_skips_windowsapps_aliases(self) -> None:
        for browser, meta in INSTALL.HOSTS.items():
            for path in meta.get("windows", {}).get("exe", []):
                self.assertNotIn("WindowsApps", path, browser)

    def test_package_activated_products_are_not_in_the_install_catalog(self) -> None:
        catalog = {(row["platform"], row["browser"]) for row in INSTALL.matrix()}
        self.assertNotIn(("macos", "arc"), catalog)
        self.assertNotIn(("windows", "arc"), catalog)
        self.assertNotIn(("windows", "duckduckgo"), catalog)

    def test_macos_librewolf_bypasses_the_disabled_homebrew_cask(self) -> None:
        # Homebrew disabled the cask on 2026-09-01 over the Gatekeeper check,
        # so the macOS cell must install the published DMG directly.
        spec = INSTALL.HOSTS["librewolf"]["macos"]
        self.assertEqual(spec["kind"], "librewolf_dmg")
        self.assertIn(
            "/Applications/LibreWolf.app/Contents/MacOS/librewolf", spec["exe"]
        )

    def test_librewolf_version_comes_from_the_release_feed(self) -> None:
        payload = io.BytesIO(b'{"tag_name": "155.0-1"}')
        with mock.patch.object(
            INSTALL.urllib.request, "urlopen", return_value=payload
        ):
            self.assertEqual(INSTALL.librewolf_latest_version(), "155.0-1")
        self.assertEqual(
            INSTALL.LIBREWOLF_MACOS_DMG.format(version="155.0-1", arch="arm64"),
            "https://dl.librewolf.net/librewolf/155.0-1/"
            "librewolf-155.0-1-macos-arm64-package.dmg",
        )

    def test_librewolf_version_rejects_an_unusable_release_tag(self) -> None:
        payload = io.BytesIO(b'{"tag_name": "nightly"}')
        with mock.patch.object(
            INSTALL.urllib.request, "urlopen", return_value=payload
        ):
            with self.assertRaises(SystemExit):
                INSTALL.librewolf_latest_version()

    def librewolf_staging(self) -> set[str]:
        return set(glob.glob(f"{tempfile.gettempdir()}/rookie-librewolf-*"))

    def test_librewolf_dmg_clears_staging_when_the_download_fails(self) -> None:
        before = self.librewolf_staging()
        with (
            mock.patch.object(INSTALL, "librewolf_latest_version", return_value="1-1"),
            mock.patch.object(
                INSTALL.urllib.request, "urlretrieve", side_effect=OSError("boom")
            ),
            self.assertRaises(OSError),
        ):
            INSTALL.install_librewolf_dmg()
        self.assertEqual(self.librewolf_staging() - before, set())

    def test_librewolf_dmg_detach_does_not_mask_the_install_failure(self) -> None:
        # A wedged disk image must not decide what the caller sees, and it must
        # not keep the download around either.
        before = self.librewolf_staging()

        def fake_run(cmd, **kwargs):
            if cmd[0] == "ditto" or cmd[:2] == ["hdiutil", "detach"]:
                raise subprocess.CalledProcessError(1, cmd)

        with (
            mock.patch.object(INSTALL, "librewolf_latest_version", return_value="1-1"),
            mock.patch.object(INSTALL.urllib.request, "urlretrieve"),
            mock.patch.object(INSTALL, "run", side_effect=fake_run),
            mock.patch.object(INSTALL.Path, "is_dir", return_value=True),
            mock.patch.object(
                INSTALL.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 1),
            ),
            self.assertRaises(subprocess.CalledProcessError) as raised,
        ):
            INSTALL.install_librewolf_dmg()

        self.assertEqual(raised.exception.cmd[0], "ditto")
        self.assertEqual(self.librewolf_staging() - before, set())

    def test_every_catalog_kind_has_an_installer_branch(self) -> None:
        for browser, meta in INSTALL.HOSTS.items():
            for platform in INSTALL.RUNNERS:
                spec = meta.get(platform)
                if spec is None:
                    continue
                self.assertIn(
                    spec["kind"],
                    INSTALL_KINDS,
                    f"{browser}/{platform}",
                )

    def test_vivaldi_and_yandex_are_real_hosted_cells(self) -> None:
        catalog = {(row["platform"], row["browser"]) for row in INSTALL.matrix()}
        for platform in INSTALL.RUNNERS:
            self.assertIn((platform, "vivaldi"), catalog)
        self.assertIn(("macos", "yandex"), catalog)
        self.assertIn(("windows", "yandex"), catalog)


if __name__ == "__main__":
    unittest.main()
