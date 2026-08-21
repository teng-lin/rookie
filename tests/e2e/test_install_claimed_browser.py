"""The silent-install catalog must stay 1:1 with nightly hosted extra browsers."""

from __future__ import annotations

import importlib.util
import stat
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

    def test_vivaldi_and_yandex_are_real_hosted_cells(self) -> None:
        catalog = {(row["platform"], row["browser"]) for row in INSTALL.matrix()}
        for platform in INSTALL.RUNNERS:
            self.assertIn((platform, "vivaldi"), catalog)
        self.assertIn(("macos", "yandex"), catalog)
        self.assertIn(("windows", "yandex"), catalog)


if __name__ == "__main__":
    unittest.main()
