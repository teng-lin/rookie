#!/usr/bin/env python3
"""Assert a Safari BinaryCookies or IE WebCache seed through Python."""

from __future__ import annotations

import os
import sys
from pathlib import Path
import time

import rookie_cookies

from cookie_manifest import find_manifest, load_manifest, verify_records


def assert_seeded(surface: str, cookies: list[dict], name: str, value: str) -> None:
    if len(cookies) != 1:
        raise RuntimeError(
            f"{surface}: expected the exact one-cookie filtered set, got {len(cookies)}"
        )
    seeded = next((cookie for cookie in cookies if cookie["name"] == name), None)
    if seeded is None:
        raise RuntimeError(f"{surface}: {name!r} missing from {len(cookies)} cookies")
    if seeded["value"] != value:
        raise RuntimeError(
            f"{surface}: expected {name}={value!r}, got {seeded['value']!r}"
        )
    expected = {
        "domain": "127.0.0.1",
        "path": "/",
        "secure": False,
        "http_only": False,
        "same_site": -1,
    }
    wrong = {
        field: (expected_value, seeded.get(field))
        for field, expected_value in expected.items()
        if seeded.get(field) != expected_value
    }
    expires = seeded.get("expires")
    now = int(time.time())
    if wrong or not isinstance(expires, int) or not now + 1800 <= expires <= now + 4500:
        raise RuntimeError(
            f"{surface}: native cookie attributes disagreed: wrong={wrong}, "
            f"expires={expires}, now={now}"
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
    manifest_path = find_manifest(path, expected_name=name)
    manifest = load_manifest(manifest_path) if manifest_path else None
    explicit = rookie_cookies.extract_from_path(str(path), domains=[domain])
    if manifest is not None:
        verify_records(
            manifest,
            "filtered_flat",
            explicit,
            surface="Python native extract_from_path",
        )
        snapshot = rookie_cookies.from_path(str(path))
        verify_records(
            manifest,
            "unfiltered_flat",
            snapshot.as_list(),
            surface="Python native from_path",
        )
        verify_records(
            manifest,
            "detailed",
            snapshot.detailed_cookies(),
            surface="Python native from_path.detailed_cookies",
        )
    else:
        assert_seeded("extract_from_path", explicit, name, value)
    discovered = []
    if browser == "safari":
        discovered = rookie_cookies.safari([domain])
        if manifest is not None:
            verify_records(
                manifest,
                "filtered_flat",
                discovered,
                surface="Python safari discovery",
            )
        else:
            assert_seeded(browser, discovered, name, value)
    print(
        f"rookie_cookies ({sys.platform}, {browser}): "
        f"{'exact cookie corpus' if manifest is not None else f'{name}={value}'} verified "
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
