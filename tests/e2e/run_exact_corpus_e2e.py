#!/usr/bin/env python3
"""Seed and exactly verify the portable real-browser cookie corpus.

The caller supplies an explicit disposable profile. This runner never performs
browser discovery and never opens an installed user's default profile.
"""

from __future__ import annotations

import argparse
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
    profile = args.profile.resolve()
    profile.mkdir(parents=True, exist_ok=True)
    port = pick_port()
    environment = os.environ.copy()
    environment.update(
        {
            "ROOKIE_E2E_COOKIE_PORT": str(port),
            "ROOKIE_E2E_DOMAIN": "127.0.0.1",
            "ROOKIE_E2E_COOKIE_NAME": "rookie_ci",
            "ROOKIE_E2E_COOKIE_VALUE": "bar",
            "ROOKIE_E2E_CHECK_BROWSER_DISCOVERY": "0",
            "ROOKIE_E2E_CHECK_RECOMMENDED_READ": "0",
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

    manifest = profile / "rookie-e2e-cookie-manifest.json"
    if not manifest.is_file():
        raise ActiveWriterError(f"browser seeder did not write {manifest}")
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

    print(
        f"exact real-browser corpus verified on Rust/Python/Node/CLI: "
        f"engine={args.engine} profile={profile} manifest={manifest}",
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
