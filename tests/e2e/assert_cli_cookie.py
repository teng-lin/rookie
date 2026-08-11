#!/usr/bin/env python3
"""Assert that the rookie-cookies CLI can read the seeded E2E cookie.

Unlike the old shell helper, this runner works on Windows, macOS, and Linux and
does not require bash or jq. It deliberately parses stdout as JSON while
capturing stderr separately, which also guards the CLI's machine-readable
output contract.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Optional, Sequence


COOKIE_NAME = "rookie_ci"
COOKIE_VALUE = "bar"


class HarnessError(RuntimeError):
    """An actionable E2E assertion failure."""


def default_cli_path() -> Path:
    executable = "rookie-cookies.exe" if os.name == "nt" else "rookie-cookies"
    return Path(__file__).resolve().parents[2] / "target" / "release" / executable


def assert_cli_cookie(
    cookies_path: Path,
    *,
    key_path: Optional[Path],
    domain: str,
    cli_path: Path,
    expected_name: Optional[str] = None,
    expected_value: Optional[str] = None,
) -> int:
    """Run the CLI and return the number of cookies in its JSON response."""
    expected_name = expected_name or os.environ.get(
        "ROOKIE_E2E_COOKIE_NAME", COOKIE_NAME
    )
    expected_value = expected_value or os.environ.get(
        "ROOKIE_E2E_COOKIE_VALUE", COOKIE_VALUE
    )
    if not cookies_path.is_file():
        raise HarnessError(f"no cookies db at {cookies_path}")
    if key_path is not None and not key_path.is_file():
        raise HarnessError(f"no browser key file at {key_path}")
    if not cli_path.is_file():
        raise HarnessError(f"no rookie-cookies CLI at {cli_path}")

    command = [
        str(cli_path),
        "--path",
        str(cookies_path),
        "--domains",
        domain,
        "--format",
        "json",
    ]
    if key_path is not None:
        command.extend(("--key-path", str(key_path)))

    environment = os.environ.copy()
    environment["RUST_LOG"] = "error"
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

    if not any(
        isinstance(cookie, dict)
        and cookie.get("name") == expected_name
        and cookie.get("value") == expected_value
        for cookie in cookies
    ):
        raise HarnessError(
            f"CLI did not return {expected_name}={expected_value}; output was: "
            f"{completed.stdout.strip()}"
        )
    return len(cookies)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cookies_path", type=Path, help="Firefox or Chromium cookies DB")
    parser.add_argument(
        "--key-path",
        type=Path,
        help="Chromium Local State/key file (required for Chromium on Windows)",
    )
    parser.add_argument(
        "--domain",
        default=os.environ.get("ROOKIE_E2E_DOMAIN", "127.0.0.1"),
        help="domain filter (default: ROOKIE_E2E_DOMAIN or 127.0.0.1)",
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
        )
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(
        f"rookie-cookies CLI: {expected_name}={expected_value} verified "
        f"({count} cookies for {args.domain})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
