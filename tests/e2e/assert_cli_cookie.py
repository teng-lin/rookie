#!/usr/bin/env python3
"""Assert that the rookie-cookies CLI exactly reads the seeded E2E corpus.

Unlike the old shell helper, this runner works on Windows, macOS, and Linux and
does not require bash or jq. It deliberately parses stdout as JSON while
capturing stderr separately, which also guards the CLI's machine-readable
output contract. Focused canaries without a corpus manifest retain their
single-cookie assertion.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Optional, Sequence

from cookie_manifest import (
    ManifestError,
    find_manifest,
    load_manifest,
    verify_records,
)
from cookie_state import assert_cookie_state, state_from_environment


COOKIE_NAME = "rookie_ci"
COOKIE_VALUE = "bar"


class HarnessError(RuntimeError):
    """An actionable E2E assertion failure."""


def default_cli_path() -> Path:
    executable = "rookie-cookies.exe" if os.name == "nt" else "rookie-cookies"
    return Path(__file__).resolve().parents[2] / "target" / "release" / executable


def assert_cli_cookie(
    cookies_path: Optional[Path],
    *,
    key_path: Optional[Path],
    domain: str,
    cli_path: Path,
    expected_name: Optional[str] = None,
    expected_value: Optional[str] = None,
    browser: Optional[str] = None,
    browser_id: Optional[str] = None,
    detailed: bool = False,
) -> int:
    """Run the CLI and return the number of cookies in its JSON response."""
    expected_name = expected_name or os.environ.get(
        "ROOKIE_E2E_COOKIE_NAME", COOKIE_NAME
    )
    expected_value = expected_value or os.environ.get(
        "ROOKIE_E2E_COOKIE_VALUE", COOKIE_VALUE
    )
    if (cookies_path is None) == (browser is None):
        raise HarnessError("provide exactly one cookies path or --browser")
    if cookies_path is not None and not cookies_path.is_file():
        raise HarnessError(f"no cookies db at {cookies_path}")
    if key_path is not None and not key_path.is_file():
        raise HarnessError(f"no browser key file at {key_path}")
    if not cli_path.is_file():
        raise HarnessError(f"no rookie-cookies CLI at {cli_path}")

    command = [str(cli_path)]
    if browser is not None:
        # `read` is an unfiltered snapshot; domain filtering belongs to
        # `report` and `from-path` in the subcommand-only CLI.
        command.extend(
            (
                "read",
                "--browser",
                browser,
                "--format",
                "detailed" if detailed else "json",
            )
        )
    else:
        command.extend(("from-path", str(cookies_path)))
        if not detailed:
            command.extend(("--domains", domain))
        command.extend(("--format", "detailed" if detailed else "json"))
        if key_path is not None:
            command.extend(("--local-state-path", str(key_path)))
        if browser_id is not None:
            command.extend(("--browser-id", browser_id))

    environment = os.environ.copy()
    environment["RUST_LOG"] = "error"
    completed = run_cli(command, cli_path=cli_path, environment=environment)

    cookies = parse_cookie_json(completed)

    manifest_source: Path | str | None = cookies_path
    if manifest_source is None:
        manifest_source = os.environ.get("ROOKIE_E2E_USER_DATA_DIR") or os.environ.get(
            "ROOKIE_E2E_FIREFOX_PROFILE"
        )
    manifest_path = find_manifest(manifest_source, expected_name=expected_name)
    if manifest_path is not None:
        try:
            manifest = load_manifest(manifest_path)
            initial_projection = (
                "detailed"
                if detailed
                else ("unfiltered_flat" if browser is not None else "filtered_flat")
            )
            verify_records(
                manifest,
                initial_projection,
                cookies,
                surface=(
                    "CLI read detailed"
                    if browser is not None and detailed
                    else (
                        "CLI from-path detailed"
                        if detailed
                        else (
                            "CLI read" if browser is not None else "CLI from-path json"
                        )
                    )
                ),
            )
            if not detailed:
                detailed_command = [str(cli_path)]
                if browser is not None:
                    detailed_command.extend(
                        ("read", "--browser", browser, "--format", "detailed")
                    )
                else:
                    detailed_command.extend(
                        ("from-path", str(cookies_path), "--format", "detailed")
                    )
                    if key_path is not None:
                        detailed_command.extend(("--local-state-path", str(key_path)))
                    if browser_id is not None:
                        detailed_command.extend(("--browser-id", browser_id))
                detailed_records = parse_cookie_json(
                    run_cli(
                        detailed_command,
                        cli_path=cli_path,
                        environment=environment,
                    )
                )
                verify_records(
                    manifest,
                    "detailed",
                    detailed_records,
                    surface="CLI read detailed"
                    if browser is not None
                    else "CLI from-path detailed",
                )
        except ManifestError as error:
            raise HarnessError(str(error)) from error
        return len(cookies)

    flat_cookies = []
    for record in cookies:
        if detailed and isinstance(record, dict):
            record = record.get("cookie")
        if isinstance(record, dict):
            flat_cookies.append(record)
    if os.environ.get("ROOKIE_E2E_REQUIRED_COOKIES_JSON"):
        try:
            required, forbidden = state_from_environment(expected_name, expected_value)
            assert_cookie_state(flat_cookies, required, forbidden, surface="CLI")
        except (AssertionError, ValueError) as error:
            raise HarnessError(str(error)) from error
        if os.environ.get("ROOKIE_E2E_EXPECT_NATIVE_FIELDS") == "1":
            if len(flat_cookies) != 1:
                raise HarnessError(
                    f"CLI native attribute assertion expected one row, got {len(flat_cookies)}"
                )
            cookie = flat_cookies[0]
            expected_fields = {
                "domain": "127.0.0.1",
                "path": "/",
                "secure": False,
                "http_only": False,
                "same_site": -1,
            }
            wrong = {
                field: (expected, cookie.get(field))
                for field, expected in expected_fields.items()
                if cookie.get(field) != expected
            }
            expires = cookie.get("expires")
            now = int(time.time())
            if (
                wrong
                or not isinstance(expires, int)
                or not now + 1800 <= expires <= now + 4500
            ):
                raise HarnessError(
                    f"CLI native attributes disagreed: wrong={wrong}, "
                    f"expires={expires}, now={now}"
                )
        return len(cookies)
    if not any(
        cookie.get("name") == expected_name and cookie.get("value") == expected_value
        for cookie in flat_cookies
    ):
        raise HarnessError(
            f"CLI did not return {expected_name}={expected_value}; output was: "
            f"{completed.stdout.strip()}"
        )
    return len(cookies)


def run_cli(
    command: list[str],
    *,
    cli_path: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
        )
    except OSError as error:
        raise HarnessError(f"failed to launch {cli_path}: {error}") from error
    if completed.returncode != 0:
        details = completed.stderr.strip() or completed.stdout.strip() or "<no output>"
        raise HarnessError(
            f"rookie-cookies exited with status {completed.returncode}: {details}"
        )
    return completed


def parse_cookie_json(completed: subprocess.CompletedProcess[str]) -> list[object]:
    try:
        cookies = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise HarnessError(
            f"rookie-cookies stdout was not valid JSON: {completed.stdout!r}; "
            f"stderr: {completed.stderr.strip()!r}"
        ) from error
    if not isinstance(cookies, list):
        raise HarnessError(
            f"rookie-cookies JSON must be an array, got {type(cookies).__name__}"
        )
    return cookies


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "cookies_path",
        type=Path,
        nargs="?",
        help="Firefox or Chromium cookies DB (omit with --browser)",
    )
    parser.add_argument(
        "--browser", help="discover the named browser instead of using an explicit path"
    )
    parser.add_argument(
        "--browser-id",
        help="Chromium credential identity for from-path (unix Keychain / libsecret)",
    )
    parser.add_argument(
        "--local-state-path",
        dest="key_path",
        type=Path,
        help="Chromium Local State/key file (required for Chromium on Windows)",
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("ROOKIE_E2E_DOMAIN", "127.0.0.1"),
        help="domain filter (default: ROOKIE_E2E_DOMAIN or 127.0.0.1)",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="assert isolation-preserving detailed output",
    )
    parser.add_argument(
        "--cli",
        dest="cli_path",
        type=Path,
        default=Path(os.environ["ROOKIE_E2E_CLI"])
        if "ROOKIE_E2E_CLI" in os.environ
        else default_cli_path(),
        help="rookie-cookies executable (default: target/release/rookie-cookies[.exe])",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        expected_name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", COOKIE_NAME)
        expected_value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", COOKIE_VALUE)
        count = assert_cli_cookie(
            args.cookies_path,
            key_path=args.key_path,
            domain=args.domain,
            cli_path=args.cli_path,
            expected_name=expected_name,
            expected_value=expected_value,
            browser=args.browser,
            browser_id=args.browser_id,
            detailed=args.detailed,
        )
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    scope = (
        f"{count} cookies returned by unfiltered {args.browser} read"
        if args.browser is not None
        else (
            f"{count} detailed cookies from the explicit path"
            if args.detailed
            else f"{count} cookies for {args.domain}"
        )
    )
    print(f"rookie-cookies CLI: {expected_name}={expected_value} verified ({scope})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
