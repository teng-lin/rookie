#!/usr/bin/env python3
"""Seed and exactly verify the portable real-browser cookie corpus.

The caller supplies an explicit disposable profile. After seeding, this runner
copies that closed profile below a registry-correct root inside a fresh
isolated home and proves discovery/recommended reads there. It never opens an
installed user's default profile.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence

from run_active_writer_e2e import (
    ActiveWriterError,
    ROOT,
    pick_port,
    run_checked,
    venv_python,
    wait_for_server,
)


REGISTRY_PATH = ROOT / "rookie-rs/browser_registry.json"


def platform_id() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def isolated_environment(root: Path) -> dict[str, str]:
    home = root / "home"
    return {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "LOCALAPPDATA": str(home / "AppData/Local"),
        "APPDATA": str(home / "AppData/Roaming"),
    }


def normalized_path_bytes(path: Path) -> bytes:
    value = os.fspath(path)
    if os.name == "nt":
        value = value.replace("\\", "/")
        value = "".join(
            character.lower() if "A" <= character <= "Z" else character
            for character in value
        )
        while len(value) > 1 and value.endswith("/"):
            value = value[:-1]
        return value.encode("utf-16-le")
    encoded = os.fsencode(value)
    while len(encoded) > 1 and encoded.endswith(b"/"):
        encoded = encoded[:-1]
    return encoded


def digest_fields(*fields: bytes) -> str:
    digest = hashlib.sha256()
    for field in fields:
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    return digest.hexdigest()


def resolve_registry_root(template: str, environment: dict[str, str]) -> Path:
    replacements = {
        "{home}": environment["HOME"],
        "{config_home}": environment["XDG_CONFIG_HOME"],
        "{xdg_config_home}": environment["XDG_CONFIG_HOME"],
        "{local_app_data}": environment["LOCALAPPDATA"],
        "{roaming_app_data}": environment["APPDATA"],
    }
    resolved = template
    for placeholder, value in replacements.items():
        resolved = resolved.replace(placeholder, value)
    if "{" in resolved or "}" in resolved or "*" in resolved:
        raise ActiveWriterError(f"unsupported core discovery root {template!r}")
    return Path(resolved)


def stage_discovered_profile(
    engine: str, browser_id: str, source: Path
) -> tuple[Path, dict[str, str], str]:
    """Copy the closed disposable profile below an isolated registry root."""

    sandbox = source.parent / f"{source.name}-discovery"
    if sandbox.exists():
        raise ActiveWriterError(f"discovery sandbox already exists: {sandbox}")
    environment = isolated_environment(sandbox)
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    entries = [
        entry
        for entry in registry["platforms"][platform_id()]
        if entry["canonical_id"] == browser_id
    ]
    if len(entries) != 1:
        raise ActiveWriterError(
            f"expected one registry entry for {platform_id()}/{browser_id}, got {len(entries)}"
        )
    root_spec = min(entries[0]["roots"], key=lambda candidate: candidate["priority"])
    root = resolve_registry_root(root_spec["template"], environment)
    if engine == "chromium":
        root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, root)
        staged_profile = root
        locator = Path("Default")
    else:
        root.mkdir(parents=True, exist_ok=True)
        staged_profile = root / "Profiles/rookie-e2e"
        staged_profile.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, staged_profile)
        (root / "profiles.ini").write_text(
            "[Profile0]\nName=rookie-e2e\nIsRelative=1\n"
            "Path=Profiles/rookie-e2e\nDefault=1\n",
            encoding="utf-8",
        )
        locator = Path("Profiles/rookie-e2e")

    canonical_root = root.resolve(strict=True)
    installation_id = digest_fields(
        b"rookie-install-v1",
        browser_id.encode(),
        root_spec["root_id"].encode(),
        root_spec["channel"].encode(),
        normalized_path_bytes(canonical_root),
    )
    profile_id = digest_fields(
        b"rookie-profile-v1",
        installation_id.encode(),
        b"relative",
        normalized_path_bytes(locator),
    )
    return staged_profile, environment, profile_id


def find_chromium_database(profile: Path) -> Path:
    for relative in ("Default/Network/Cookies", "Default/Cookies"):
        candidate = profile / relative
        if candidate.is_file():
            return candidate.resolve()
    raise ActiveWriterError(f"no Chromium cookie database below {profile}")


def seeder_command(args: argparse.Namespace, base_url: str) -> list[str]:
    if args.engine == "chromium":
        command = [
            "node",
            "tests/e2e/seed_chromium_cookie.mjs",
            args.channel,
            str(args.profile),
            base_url,
        ]
    else:
        command = [
            "node",
            "tests/e2e/seed_firefox_cookie.mjs",
            str(args.profile),
            base_url,
        ]
    if args.xvfb:
        if shutil.which("xvfb-run") is None:
            raise ActiveWriterError("--xvfb requested but xvfb-run is unavailable")
        command = ["xvfb-run", "-a", *command]
    return command


def run(args: argparse.Namespace) -> None:
    seeded_profile = args.profile.resolve()
    seeded_profile.mkdir(parents=True, exist_ok=True)
    port = pick_port()
    environment = os.environ.copy()
    environment.update(
        {
            "ROOKIE_E2E_COOKIE_PORT": str(port),
            "ROOKIE_E2E_DOMAIN": "127.0.0.1",
            "ROOKIE_E2E_COOKIE_NAME": "rookie_ci",
            "ROOKIE_E2E_COOKIE_VALUE": "bar",
        }
    )
    server = subprocess.Popen(
        [sys.executable, "-u", "tests/e2e/cookie_server.py"],
        cwd=str(ROOT),
        env=environment,
    )
    try:
        wait_for_server(port, server, args.timeout)
        run_checked(
            seeder_command(args, f"http://127.0.0.1:{port}/"),
            environment,
            "exact-corpus-seed",
        )
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()

    manifest = seeded_profile / "rookie-e2e-cookie-manifest.json"
    if not manifest.is_file():
        raise ActiveWriterError(f"browser seeder did not write {manifest}")
    profile, discovery_environment, expected_profile_id = stage_discovered_profile(
        args.engine, args.browser_id, seeded_profile
    )
    environment.update(discovery_environment)
    environment.update(
        {
            "ROOKIE_E2E_CHECK_BROWSER_DISCOVERY": "1",
            "ROOKIE_E2E_CHECK_RECOMMENDED_READ": "1",
            "ROOKIE_E2E_EXPECTED_PROFILE_ID": expected_profile_id,
            "ROOKIE_E2E_TARGET_BROWSER": args.browser_id,
        }
    )
    manifest = profile / "rookie-e2e-cookie-manifest.json"
    environment["ROOKIE_E2E_COOKIE_MANIFEST"] = str(manifest)
    python = venv_python()
    if args.engine == "chromium":
        database = find_chromium_database(profile)
        environment.update(
            {
                "ROOKIE_E2E_USER_DATA_DIR": str(profile),
                "ROOKIE_E2E_COOKIE_DB": str(database),
                "ROOKIE_E2E_BROWSER_ID": args.browser_id,
            }
        )
        run_checked(
            [
                "cargo",
                "test",
                "--test",
                "e2e_chrome",
                "--locked",
                "--",
                "--ignored",
                "--nocapture",
            ],
            environment,
            "exact-corpus",
        )
        run_checked(
            [str(python), "tests/e2e/assert_chrome_cookie.py"],
            environment,
            "exact-corpus",
        )
        run_checked(
            ["node", "tests/e2e/assert_chrome_cookie.mjs"], environment, "exact-corpus"
        )
        cli = [str(python), "tests/e2e/assert_cli_cookie.py", str(database)]
        if sys.platform == "win32":
            cli.extend(["--local-state-path", str(profile / "Local State")])
        else:
            cli.extend(["--browser-id", args.browser_id])
        run_checked(cli, environment, "exact-corpus")
        run_checked(
            [
                str(python),
                "tests/e2e/assert_cli_cookie.py",
                "--browser",
                args.browser_id,
            ],
            environment,
            "exact-corpus-recommended",
        )
    else:
        database = (profile / "cookies.sqlite").resolve(strict=True)
        environment.update(
            {
                "ROOKIE_E2E_FIREFOX_PROFILE": str(profile),
                "ROOKIE_E2E_COOKIE_DB": str(database),
                "ROOKIE_E2E_BROWSER_ID": args.browser_id,
            }
        )
        run_checked(
            [
                "cargo",
                "test",
                "--test",
                "e2e_firefox",
                "--locked",
                "--",
                "--ignored",
                "--nocapture",
            ],
            environment,
            "exact-corpus",
        )
        run_checked(
            [str(python), "tests/e2e/assert_firefox_cookie.py"],
            environment,
            "exact-corpus",
        )
        run_checked(
            ["node", "tests/e2e/assert_firefox_cookie.mjs"], environment, "exact-corpus"
        )
        run_checked(
            [str(python), "tests/e2e/assert_cli_cookie.py", str(database)],
            environment,
            "exact-corpus",
        )
        run_checked(
            [
                str(python),
                "tests/e2e/assert_cli_cookie.py",
                "--browser",
                args.browser_id,
            ],
            environment,
            "exact-corpus-recommended",
        )

    print(
        f"exact real-browser corpus verified on Rust/Python/Node/CLI: "
        f"engine={args.engine} profile={profile} profile_id={expected_profile_id} "
        f"manifest={manifest}",
        flush=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=("chromium", "firefox"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--channel", default="chrome")
    parser.add_argument("--browser-id", default="chrome")
    parser.add_argument("--xvfb", action="store_true")
    parser.add_argument("--timeout", type=float, default=120)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        run(args)
    except (
        ActiveWriterError,
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"exact corpus e2e failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
