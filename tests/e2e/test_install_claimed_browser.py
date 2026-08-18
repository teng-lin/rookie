"""The silent-install catalog must stay 1:1 with nightly hosted extra browsers."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import test_browser_coverage as coverage


MODULE_PATH = Path(__file__).with_name("install_claimed_browser.py")
SPEC = importlib.util.spec_from_file_location("install_claimed_browser", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)

# Seeded by e2e.yml without this installer (image-provided Chrome/Firefox/Edge
# or Playwright Chromium).
PREINSTALLED = frozenset(
    {
        ("linux", "chrome"),
        ("linux", "chromium"),
        ("linux", "edge"),
        ("linux", "firefox"),
        ("macos", "chrome"),
        ("macos", "chromium"),
        ("macos", "edge"),
        ("macos", "firefox"),
        ("windows", "chrome"),
        ("windows", "chromium"),
        ("windows", "edge"),
        ("windows", "firefox"),
    }
)


class InstallCatalogTests(unittest.TestCase):
    def test_every_catalog_cell_is_nightly_hosted(self) -> None:
        catalog = {
            (row["platform"], row["browser"]) for row in INSTALL.matrix()
        }
        extra = coverage.NIGHTLY_HOSTED - PREINSTALLED
        self.assertEqual(catalog, extra)


if __name__ == "__main__":
    unittest.main()
