#!/usr/bin/env python3
"""Exercise every claimed browser ID on this OS with isolated fixtures.

Release/manual lane; never launches a browser. Every ID must appear in
``supported_browsers()``. Feasible fixture-lane Chromium and Gecko cells get a
registry-correct temporary root, exact profile/source discovery checks, and
detailed explicit-path extraction. Gecko also exercises profile-scoped
``read``. Windows retains its separate current-user DPAPI engine fixture; no
per-ID fixture claims platform crypto coverage.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import rookie_cookies

from browser_coverage_contract import assert_observed_depth, load_coverage
from cookie_manifest import paths_refer_to_same_file


COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
REGISTRY_PATH = Path(__file__).resolve().parents[2] / "rookie-rs/browser_registry.json"


def this_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def load_rows(platform: str) -> list[dict]:
    doc = load_coverage()
    return [row for row in doc["coverage"] if row["platform"] == platform]


def isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "LOCALAPPDATA": str(home / "AppData/Local"),
        "APPDATA": str(home / "AppData/Roaming"),
    }


def registry_entry(platform: str, browser: str) -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    matches = [
        entry
        for entry in registry["platforms"][platform]
        if entry["canonical_id"] == browser
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"expected one registry entry for {platform}/{browser}, got {len(matches)}"
        )
    return matches[0]


def resolve_root(template: str, environment: dict[str, str]) -> Path:
    replacements = {
        "{home}": environment["HOME"],
        "{config_home}": environment["XDG_CONFIG_HOME"],
        "{xdg_config_home}": environment["XDG_CONFIG_HOME"],
        "{local_app_data}": environment["LOCALAPPDATA"],
        "{roaming_app_data}": environment["APPDATA"],
    }
    value = template
    for placeholder, replacement in replacements.items():
        value = value.replace(placeholder, replacement)
    value = value.replace("*", "rookie-fixture")
    if "{" in value or "}" in value:
        raise SystemExit(f"unresolved registry root template {template!r}")
    return Path(value)


def fixture_root(platform: str, browser: str, environment: dict[str, str]) -> Path:
    entry = registry_entry(platform, browser)
    roots = sorted(entry["roots"], key=lambda root: root["priority"])
    if not roots:
        raise SystemExit(f"registry browser {browser!r} has no discovery roots")
    return resolve_root(roots[0]["template"], environment)


def write_gecko_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def write_chromium_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    try:
        connection.executescript(
            """
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
            INSERT INTO meta VALUES ('version', '23');
            CREATE TABLE cookies (
              host_key TEXT NOT NULL, path TEXT NOT NULL,
              is_secure INTEGER NOT NULL, expires_utc INTEGER NOT NULL,
              name TEXT NOT NULL, value TEXT NOT NULL,
              encrypted_value BLOB NOT NULL, is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO cookies VALUES "
            "('.example.test', '/', 1, 13348540800000000, "
            "'rookie_ci', 'bar', X'', 1, 1)"
        )
        connection.commit()
    finally:
        connection.close()


def assert_detailed(snapshot: object) -> None:
    detailed = snapshot.detailed_cookies()
    match = next(
        (record for record in detailed if record["cookie"]["name"] == "rookie_ci"),
        None,
    )
    if match is None or match["cookie"]["value"] != "bar":
        raise SystemExit("detailed fixture output omitted rookie_ci=bar")


def assert_discovered_source(browser: str, database: Path) -> dict:
    profiles = rookie_cookies.browser_profiles(browser)
    matching = [
        profile
        for profile in profiles
        if any(
            paths_refer_to_same_file(source["path"], database)
            for source in profile["sources"]
        )
    ]
    if len(matching) != 1:
        raise SystemExit(
            f"{browser} discovery found {len(matching)} profiles for {database}; "
            f"profiles={profiles!r}"
        )
    identity = matching[0]["profile"]
    if identity["browser_id"] != browser:
        raise SystemExit(f"{browser} discovery returned {identity!r}")
    return identity


def exercise_fixture_cell(
    platform: str, row: dict, environment: dict[str, str]
) -> None:
    browser = row["browser"]
    engine = row["engine"]
    observed = {"registry_id": "fixture"}
    root = fixture_root(platform, browser, environment)

    if engine == "chromium":
        database = root / "Default/Network/Cookies"
        write_chromium_db(database)
        (root / "Local State").write_text(
            json.dumps(
                {
                    "profile": {
                        "last_used": "Default",
                        "info_cache": {"Default": {"name": "Default"}},
                    }
                }
            ),
            encoding="utf-8",
        )
        snapshot = rookie_cookies.from_path(
            str(database), include_expired=True, plaintext_only=True
        )
        assert_seeded(snapshot.as_list())
        assert_detailed(snapshot)
        assert_discovered_source(browser, database)
        observed.update(
            {"explicit_path": "fixture", "detailed": "fixture", "discovery": "fixture"}
        )
    elif engine == "gecko":
        profile = root / "Profiles/rookie-fixture"
        database = profile / "cookies.sqlite"
        write_gecko_db(database)
        root.mkdir(parents=True, exist_ok=True)
        (root / "profiles.ini").write_text(
            "[Profile0]\nName=rookie-fixture\nIsRelative=1\n"
            "Path=Profiles/rookie-fixture\nDefault=1\n",
            encoding="utf-8",
        )
        direct = rookie_cookies.from_path(str(database), include_expired=True)
        assert_seeded(direct.as_list())
        assert_detailed(direct)
        identity = assert_discovered_source(browser, database)
        recommended = rookie_cookies.read(
            browser=browser,
            profile=identity["profile_id"],
            include_expired=True,
        )
        if (
            recommended.browser_id != browser
            or recommended.profile_id != identity["profile_id"]
        ):
            raise SystemExit(f"{browser} recommended read selected the wrong identity")
        assert_seeded(recommended.as_list())
        assert_detailed(recommended)
        observed.update(
            {
                "explicit_path": "fixture",
                "detailed": "fixture",
                "discovery": "fixture",
                "recommended_read": "fixture",
            }
        )

    assert_observed_depth(row, observed)


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
    missing = sorted(row["browser"] for row in rows if row["browser"] not in supported)
    if missing:
        raise SystemExit(
            f"supported_browsers() is missing claimed ids {missing}; "
            f"got {sorted(supported)}"
        )

    with tempfile.TemporaryDirectory(prefix="rookie-claimed-") as temp:
        environment = isolated_environment(Path(temp))
        os.environ.update(environment)
        os.environ.pop("CHROME_CONFIG_HOME", None)
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

        for row in rows:
            if row["lane"] == "release_fixture":
                exercise_fixture_cell(platform, row, environment)

    print(f"claimed-browser fixtures ok on {platform} ({len(rows)} ids)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default=this_platform())
    args = parser.parse_args()
    return run(args.platform)


if __name__ == "__main__":
    raise SystemExit(main())
