#!/usr/bin/env python3
"""Compare report semantics across Rust, Python, Node, and CLI processes.

The fixture deliberately covers two profiles, a selected profile, one broken
source, a missing installation, a Linux partial-discovery root, a registry-only
browser, and an unknown ID. Each public surface runs in its own process.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[2]


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        result = {snake(key): normalize(item) for key, item in value.items()}
        if {"domain", "name", "value"}.issubset(result):
            result.setdefault("expires", None)
        if {"browser_id", "installation_id", "profile_id"}.issubset(result):
            result.setdefault("display_name", None)
        if {"code", "stage", "severity", "occurrences"}.issubset(result):
            for key in ("browser_id", "installation_id", "profile_id"):
                result.setdefault(key, None)
        return result
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def firefox_root(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library/Application Support/Firefox"
    if sys.platform == "win32":
        return home / "AppData/Roaming/Mozilla/Firefox"
    return home / ".mozilla/firefox"


def librewolf_root(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library/Application Support/librewolf"
    if sys.platform == "win32":
        return home / "AppData/Roaming/librewolf"
    return home / ".librewolf"


def seed_database(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE moz_cookies (
              host TEXT NOT NULL, path TEXT NOT NULL, isSecure INTEGER NOT NULL,
              expiry INTEGER NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
              isHttpOnly INTEGER NOT NULL, sameSite INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            "INSERT INTO moz_cookies VALUES (?, '/', 0, 1700000000, ?, ?, 0, 0)",
            (".example.test", f"profile-{value}", value),
        )


def seed_home(home: Path) -> None:
    root = firefox_root(home)
    root.mkdir(parents=True)
    profiles = [("rookie-a", "Profiles/a"), ("rookie-b", "Profiles/b")]
    root.joinpath("profiles.ini").write_text(
        "".join(
            f"[Profile{index}]\nName={name}\nIsRelative=1\nPath={path}\n"
            + ("Default=1\n" if index == 0 else "")
            + "\n"
            for index, (name, path) in enumerate(profiles)
        ),
        encoding="utf-8",
    )
    for name, path in profiles:
        seed_database(root / path / "cookies.sqlite", name)

    broken = librewolf_root(home)
    broken_profile = broken / "Profiles/broken"
    broken_profile.mkdir(parents=True)
    broken.joinpath("profiles.ini").write_text(
        "[Profile0]\nName=broken\nIsRelative=1\nPath=Profiles/broken\nDefault=1\n",
        encoding="utf-8",
    )
    broken_profile.joinpath("cookies.sqlite").write_bytes(b"not sqlite")

    if sys.platform.startswith("linux"):
        bad_ini = home / "snap/firefox/common/.mozilla/firefox/profiles.ini"
        bad_ini.mkdir(parents=True)


def commands(args: argparse.Namespace) -> dict[str, list[str]]:
    return {
        "rust": [args.rust],
        "python": [args.python, str(REPO / "tests/e2e/report_surface_python.py")],
        "node": [args.node, str(REPO / "tests/e2e/report_surface_node.mjs")],
        "cli": [args.cli],
    }


def surface_args(surface: str, request: list[str]) -> list[str]:
    if surface != "cli":
        return request
    if request[0] == "profiles":
        return ["--list-profiles", "--browser", request[1]]
    if request[0] == "report":
        result = ["--report", "--browser", request[1]]
        if len(request) == 3:
            result.extend(["--profile", request[2]])
        return result
    return ["--report"]


def invoke(command: list[str], surface: str, request: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, *surface_args(surface, request)],
        cwd=REPO,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def validate_raw_report(surface: str, value: Any) -> None:
    if not isinstance(value, dict) or "status" not in value:
        return
    schema_key = "schemaVersion" if surface == "node" else "schema_version"
    assert value.get(schema_key) == 1, (surface, value)
    assert "termination" in value, (surface, value)

    issue_keys = {
        "cause",
        "provider",
        "tier",
        "retryability",
    }
    if surface == "node":
        issue_keys = {"cause", "provider", "tier", "retryability"}

    def walk(item: Any) -> None:
        if isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, dict):
            if {"code", "stage", "severity", "occurrences"}.issubset(item):
                missing = issue_keys.difference(item)
                assert not missing, (surface, missing, item)
                if item["cause"] == "credential_provider":
                    assert item["provider"], (surface, item)
                    assert item["tier"], (surface, item)
                    assert item["retryability"] in {
                        "retryable",
                        "not_retryable",
                    }, (surface, item)
            for child in item.values():
                walk(child)

    walk(value)


def compare(request: list[str], launchers: dict[str, list[str]], env: dict[str, str]) -> Any:
    observed: dict[str, Any] = {}
    for surface, command in launchers.items():
        result = invoke(command, surface, request, env)
        if result.returncode != 0:
            raise AssertionError(f"{surface} {request} failed: {result.stderr}")
        raw = json.loads(result.stdout)
        validate_raw_report(surface, raw)
        observed[surface] = normalize(raw)
    reference = observed["rust"]
    for surface, value in observed.items():
        if value != reference:
            raise AssertionError(f"{request}: {surface} differs from Rust\n{value!r}\n{reference!r}")
    return reference


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--cli", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="rookie-report-surfaces-") as temp:
        home = Path(temp)
        seed_home(home)
        env = os.environ.copy()
        env.update(
            HOME=str(home),
            USERPROFILE=str(home),
            APPDATA=str(home / "AppData/Roaming"),
            LOCALAPPDATA=str(home / "AppData/Local"),
            XDG_CONFIG_HOME=str(home / ".config"),
            RUST_LOG="error",
        )
        launchers = commands(args)

        profiles = compare(["profiles", "firefox"], launchers, env)
        assert len(profiles) == 2
        profile_id = profiles[1]["profile"]["profile_id"]

        firefox = compare(["report", "firefox"], launchers, env)
        assert len(firefox["profiles"]) == 2
        assert firefox["status"] == "complete", firefox["status"]
        if sys.platform.startswith("linux"):
            assert firefox["issues"], "the broken snap root must remain diagnostic"

        selected = compare(["report", "firefox", profile_id], launchers, env)
        assert len(selected["profiles"]) == 1
        assert selected["profiles"][0]["profile"]["profile_id"] == profile_id

        failed = compare(["report", "librewolf"], launchers, env)
        assert failed["status"] == "failed"

        absent = compare(["report", "chrome"], launchers, env)
        assert absent["status"] == "no_sources"

        registry_only_ids = {
            "darwin": ["coccoc", "yandex"],
            "win32": ["coccoc", "duckduckgo", "yandex"],
        }.get(sys.platform, [])
        for browser_id in registry_only_ids:
            registry_only = compare(["report", browser_id], launchers, env)
            assert registry_only["status"] == "no_sources"

        compare(["load-report"], launchers, env)

        for surface, command in launchers.items():
            result = invoke(command, surface, ["report", "not_a_browser"], env)
            assert result.returncode != 0, surface
            assert not result.stdout, f"{surface} wrote partial JSON for unknown ID"

    print("Rust, Python, Node, and CLI report semantics match")


if __name__ == "__main__":
    main()
