#!/usr/bin/env python3
"""Assert a Safari BinaryCookies or IE WebCache seed through Python."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import rookie_cookies


def assert_seeded(surface: str, cookies: list[dict], name: str, value: str) -> None:
    seeded = next((cookie for cookie in cookies if cookie["name"] == name), None)
    if seeded is None:
        raise RuntimeError(f"{surface}: {name!r} missing from {len(cookies)} cookies")
    if seeded["value"] != value:
        raise RuntimeError(
            f"{surface}: expected {name}={value!r}, got {seeded['value']!r}"
        )


def main() -> int:
    browser = os.environ.get("ROOKIE_E2E_BROWSER_ID", "")
    path_raw = os.environ.get("ROOKIE_E2E_COOKIE_DB", "")
    if browser not in ("safari", "internet_explorer") or not path_raw:
        print(
            "ROOKIE_E2E_BROWSER_ID and ROOKIE_E2E_COOKIE_DB must identify Safari or IE",
            file=sys.stderr,
        )
        return 2
    path = Path(path_raw)
    if not path.is_file():
        print(f"no native cookie store at {path}", file=sys.stderr)
        return 1

    domain = os.environ.get("ROOKIE_E2E_DOMAIN", "127.0.0.1")
    name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    explicit = rookie_cookies.extract_from_path(str(path), domains=[domain])
    assert_seeded("extract_from_path", explicit, name, value)
    discovered = []
    if browser == "safari":
        discovered = rookie_cookies.safari([domain])
        assert_seeded(browser, discovered, name, value)
    print(
        f"rookie_cookies ({sys.platform}, {browser}): {name}={value} verified "
        f"(explicit={len(explicit)}"
        + (f", discovered={len(discovered)})" if browser == "safari" else ")")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"native Python assertion failed: {error}", file=sys.stderr)
        raise
