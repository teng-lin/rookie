#!/usr/bin/env python3
"""Run one macOS E2E command with a disposable Safe Storage keychain first."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
from typing import Sequence


SECURITY = Path("/usr/bin/security")
TEST_PASSWORD = "mock_password"


class EphemeralKeychainError(RuntimeError):
    pass


def security(*arguments: str, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SECURITY), *arguments],
        check=True,
        capture_output=capture_output,
        text=True,
        encoding="utf-8",
    )


def user_keychain_search_list() -> list[str]:
    completed = security("list-keychains", "-d", "user", capture_output=True)
    keychains = shlex.split(completed.stdout)
    if any(not Path(keychain).is_absolute() for keychain in keychains):
        raise EphemeralKeychainError("macOS returned a non-absolute user keychain path")
    return keychains


def run_isolated(
    command: Sequence[str],
    *,
    service: str,
    accounts: Sequence[str],
) -> int:
    if sys.platform != "darwin":
        raise EphemeralKeychainError("ephemeral Keychain wrapper requires macOS")
    if not command:
        raise EphemeralKeychainError("a child command is required")
    if not service.strip() or not accounts or any(not account.strip() for account in accounts):
        raise EphemeralKeychainError("Safe Storage service/accounts must be non-empty")

    original = user_keychain_search_list()
    scratch_parent = os.environ.get("RUNNER_TEMP")
    if scratch_parent and not Path(scratch_parent).is_dir():
        raise EphemeralKeychainError("RUNNER_TEMP is not an existing directory")
    changed_search_list = False
    with tempfile.TemporaryDirectory(
        prefix="rookie-keychain-",
        dir=scratch_parent,
    ) as temporary:
        keychain = str(Path(temporary) / "rookie-e2e.keychain-db")
        keychain_password = secrets.token_urlsafe(24)
        try:
            security("create-keychain", "-p", keychain_password, keychain)
            security("unlock-keychain", "-p", keychain_password, keychain)
            security("set-keychain-settings", "-lut", "21600", keychain)
            for account in dict.fromkeys(accounts):
                security(
                    "add-generic-password",
                    "-A",
                    "-a",
                    account,
                    "-s",
                    service,
                    "-w",
                    TEST_PASSWORD,
                    keychain,
                )
            # Keep the user's original list available to other applications,
            # but put the disposable exact-match items first for this short run.
            security("list-keychains", "-d", "user", "-s", keychain, *original)
            changed_search_list = True
            child_environment = os.environ.copy()
            # Discovery lanes use a disposable HOME so they cannot find a
            # normal browser profile. Give those lanes enough information to
            # register this same disposable keychain in that isolated HOME.
            child_environment["ROOKIE_E2E_EPHEMERAL_KEYCHAIN"] = keychain
            child_environment["ROOKIE_E2E_EPHEMERAL_KEYCHAIN_PASSWORD"] = (
                keychain_password
            )
            completed = subprocess.run(
                list(command), check=False, env=child_environment
            )
            return completed.returncode
        finally:
            restore_error: BaseException | None = None
            if changed_search_list:
                try:
                    security("list-keychains", "-d", "user", "-s", *original)
                except BaseException as error:  # restoration is safety-critical
                    restore_error = error
            try:
                security("delete-keychain", keychain)
            except subprocess.CalledProcessError:
                if Path(keychain).exists():
                    raise
            if restore_error is not None:
                raise EphemeralKeychainError(
                    "failed to restore the original macOS user keychain search list"
                ) from restore_error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True)
    parser.add_argument("--account", action="append", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run_isolated(command, service=args.service, accounts=args.account)
    except (EphemeralKeychainError, OSError, subprocess.CalledProcessError) as error:
        print(f"ephemeral Keychain E2E failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
