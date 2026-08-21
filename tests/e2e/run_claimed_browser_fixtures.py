#!/usr/bin/env python3
"""Exercise every claimed browser_id on this OS with engine fixtures.

Release / manual lane. Does not launch a real browser. Gecko ids share one
generated cookies.sqlite. Windows Chromium extraction uses one current-user
DPAPI fixture (not per-id ``browser_id``). Every claimed id must appear in
``supported_browsers()``.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import rookie_cookies


COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")


def this_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def load_rows(platform: str) -> list[dict]:
    doc = json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))
    return [row for row in doc["coverage"] if row["platform"] == platform]


def write_gecko_db(path: Path) -> None:
    connection = sqlite3.connect(str(path))
    try:
        connection.execute(
            """
            CREATE TABLE moz_cookies (
              host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
              expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
              isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES "
            "('.example.test', '/', 1, 4102444800, 'rookie_ci', 'bar', 1, 0)"
        )
        connection.commit()
    finally:
        connection.close()


def assert_seeded(cookies: list) -> None:
    match = next((cookie for cookie in cookies if cookie["name"] == "rookie_ci"), None)
    if match is None:
        raise SystemExit(f"seeded cookie missing among {len(cookies)} rows")
    if match["value"] != "bar":
        raise SystemExit(f"seeded cookie value was {match['value']!r}, expected 'bar'")


def run(platform: str) -> int:
    rows = load_rows(platform)
    if not rows:
        raise SystemExit(f"no coverage rows for platform {platform!r}")

    supported = {
        item if isinstance(item, str) else item["id"]
        for item in rookie_cookies.supported_browsers()
    }
    missing = sorted(
        row["browser"] for row in rows if row["browser"] not in supported
    )
    if missing:
        raise SystemExit(
            f"supported_browsers() is missing claimed ids {missing}; "
            f"got {sorted(supported)}"
        )

    with tempfile.TemporaryDirectory(prefix="rookie-claimed-") as temp:
        gecko_db = Path(temp) / "cookies.sqlite"
        write_gecko_db(gecko_db)
        gecko_cookies = rookie_cookies.from_path(
            str(gecko_db), include_expired=True
        ).as_list()
        assert_seeded(gecko_cookies)

        if sys.platform != "win32":
            missing_db = str(Path(temp) / "missing-Cookies")
            for row in rows:
                if row["engine"] != "chromium":
                    continue
                try:
                    rookie_cookies.chromium_cookies_from_path(
                        missing_db, {"browser_id": row["browser"]}
                    )
                except Exception as error:
                    message = str(error)
                    if "unknown browser id" in message or "not Chromium" in message:
                        raise SystemExit(
                            f"browser_id {row['browser']!r} is not a valid Chromium "
                            f"identity: {message}"
                        ) from error

        if sys.platform == "win32":
            user_data = Path(temp) / "chromium-user-data"
            fixture = Path(__file__).with_name("create_windows_dpapi_fixture.py")
            completed = subprocess.run(
                [sys.executable, str(fixture), str(user_data)],
                check=False,
            )
            if completed.returncode != 0:
                raise SystemExit("failed to create Windows DPAPI fixture")
            cookies_db = user_data / "Default" / "Network" / "Cookies"
            local_state = user_data / "Local State"
            cookies = rookie_cookies.chromium_cookies_from_path(
                str(cookies_db),
                {
                    "domains": ["example.test"],
                    "local_state_path": str(local_state),
                },
            )
            assert_seeded(cookies)

            octo_profile = (
                Path(temp)
                / "AppData"
                / "Local"
                / "Octo Browser"
                / "tmp"
                / "fixture-profile-uuid"
            )
            completed_octo = subprocess.run(
                [sys.executable, str(fixture), str(octo_profile)],
                check=False,
            )
            if completed_octo.returncode != 0:
                raise SystemExit("failed to create Octo Browser DPAPI fixture")
            octo_cookies_db = octo_profile / "Default" / "Network" / "Cookies"
            octo_local_state = octo_profile / "Local State"
            octo_cookies = rookie_cookies.chromium_cookies_from_path(
                str(octo_cookies_db),
                {
                    "domains": ["example.test"],
                    "local_state_path": str(octo_local_state),
                },
            )
            assert_seeded(octo_cookies)

    print(f"claimed-browser fixtures ok on {platform} ({len(rows)} ids)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default=this_platform())
    args = parser.parse_args()
    return run(args.platform)


if __name__ == "__main__":
    raise SystemExit(main())
