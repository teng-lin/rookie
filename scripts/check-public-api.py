#!/usr/bin/env python3
"""Compare cargo-public-api output with per-OS, per-feature baselines."""

from __future__ import annotations

import argparse
import difflib
import json
import subprocess
import sys
from datetime import date
from pathlib import Path


TOOL_VERSION = "0.52.0"
# cargo-public-api 0.52.0 --locked pins rustdoc-types 0.57.3. Its advertised
# minimum nightly (2025-08-02) still emits format 55 and fails on the required
# ExternalCrate.path field; 2025-11-23 is the first tested format-57 nightly.
NIGHTLY = "nightly-2025-11-23"
PLATFORMS = {"linux", "macos", "windows"}
FEATURE_SETS = {
    "all-features": ["--all-features"],
    "no-default-features": ["--no-default-features"],
}
CHANGES = {"added", "removed", "missing-baseline"}


class PublicApiCommandError(RuntimeError):
    """A cargo-public-api command failed with a user-facing diagnostic."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--bootstrap", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args()


def load_exceptions(path: Path) -> list[dict[str, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("exceptions"), list):
        raise ValueError(f"invalid exception metadata schema in {path}")

    exceptions = data["exceptions"]
    required = {"platform", "feature_set", "change", "item", "reason", "remove_by"}
    seen: set[tuple[str, str, str, str]] = set()
    for exception in exceptions:
        if set(exception) != required or not all(
            isinstance(exception[field], str) and exception[field].strip() for field in required
        ):
            raise ValueError(f"exception must have six non-empty string fields: {exception!r}")
        if exception["platform"] not in PLATFORMS:
            raise ValueError(f"unknown exception platform: {exception!r}")
        if exception["feature_set"] not in FEATURE_SETS:
            raise ValueError(f"unknown exception feature set: {exception!r}")
        if exception["change"] not in CHANGES:
            raise ValueError(f"unknown exception change: {exception!r}")
        try:
            remove_by = date.fromisoformat(exception["remove_by"])
        except ValueError as error:
            raise ValueError(
                f"exception remove_by must be an ISO date (YYYY-MM-DD): {exception!r}"
            ) from error
        if exception["remove_by"] != remove_by.isoformat():
            raise ValueError(
                f"exception remove_by must use canonical YYYY-MM-DD form: {exception!r}"
            )
        if remove_by < date.today():
            raise ValueError(f"expired public API exception: {exception!r}")
        key = tuple(exception[field] for field in ("platform", "feature_set", "change", "item"))
        if key in seen:
            raise ValueError(f"duplicate exception: {exception!r}")
        seen.add(key)
    return exceptions


def tool_version() -> str:
    try:
        result = subprocess.run(
            ["cargo", "public-api", "--version"],
            check=True,
            text=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as error:
        diagnostic = (error.stderr or error.stdout or str(error)).strip()
        raise PublicApiCommandError(diagnostic) from None
    return result.stdout.strip().rsplit(" ", 1)[-1]


def render_public_api(repo: Path, feature_args: list[str]) -> str:
    command = [
        "cargo",
        f"+{NIGHTLY}",
        "public-api",
        "--manifest-path",
        str(repo / "rookie-rs" / "Cargo.toml"),
        "--omit",
        "blanket-impls",
        "--color=never",
        *feature_args,
    ]
    try:
        result = subprocess.run(command, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        diagnostic = (error.stderr or error.stdout or str(error)).strip()
        raise PublicApiCommandError(diagnostic) from None
    return result.stdout.rstrip("\n") + "\n"


def scoped_exceptions(
    exceptions: list[dict[str, str]], platform: str, feature_set: str
) -> list[dict[str, str]]:
    return [
        exception
        for exception in exceptions
        if exception["platform"] == platform and exception["feature_set"] == feature_set
    ]


def compare_with_exceptions(
    expected: str,
    actual: str,
    exceptions: list[dict[str, str]],
    label: str,
) -> bool:
    expected_lines = expected.splitlines()
    actual_lines = actual.splitlines()
    active: set[tuple[str, str]] = set()

    for exception in exceptions:
        change = exception["change"]
        item = exception["item"]
        if change == "added" and item in actual_lines and item not in expected_lines:
            actual_lines.remove(item)
            active.add((change, item))
        elif change == "removed" and item in expected_lines and item not in actual_lines:
            expected_lines.remove(item)
            active.add((change, item))

    stale = [
        exception
        for exception in exceptions
        if exception["change"] != "missing-baseline"
        and (exception["change"], exception["item"]) not in active
    ]
    if stale:
        print(f"stale or mismatched public API exceptions for {label}: {stale!r}", file=sys.stderr)
        return False
    if expected_lines == actual_lines:
        return True

    print(f"public API mismatch for {label}:", file=sys.stderr)
    print(
        "\n".join(
            difflib.unified_diff(
                expected_lines,
                actual_lines,
                fromfile=f"committed/{label}",
                tofile=f"actual/{label}",
                lineterm="",
            )
        ),
        file=sys.stderr,
    )
    return False


def main() -> int:
    args = parse_args()
    repo = Path(__file__).resolve().parents[1]
    baseline_dir = repo / "rookie-rs" / "public-api"
    exception_file = baseline_dir / "temporary-exceptions.json"

    try:
        installed_tool_version = tool_version()
    except PublicApiCommandError as error:
        print(f"cargo-public-api failed: {error}", file=sys.stderr)
        return 2

    if installed_tool_version != TOOL_VERSION:
        print(
            f"cargo-public-api {TOOL_VERSION} is required; install with "
            f"`cargo install cargo-public-api --version {TOOL_VERSION} --locked`",
            file=sys.stderr,
        )
        return 2

    try:
        exceptions = load_exceptions(exception_file)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        return 2

    success = True
    for feature_set, feature_args in FEATURE_SETS.items():
        filename = f"{args.platform}-{feature_set}.txt"
        try:
            actual = render_public_api(repo, feature_args)
        except PublicApiCommandError as error:
            print(f"cargo-public-api failed for {filename}: {error}", file=sys.stderr)
            return 2
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            (args.output_dir / filename).write_text(actual, encoding="utf-8")

        baseline = baseline_dir / filename
        current_exceptions = scoped_exceptions(exceptions, args.platform, feature_set)
        missing = [
            exception
            for exception in current_exceptions
            if exception["change"] == "missing-baseline" and exception["item"] == filename
        ]
        if not baseline.exists():
            if args.bootstrap and len(missing) == 1:
                print(f"staged {filename}; commit the native artifact and remove its exception")
                continue
            print(f"missing public API baseline: {baseline}", file=sys.stderr)
            success = False
            continue
        if missing:
            print(f"stale missing-baseline exception for {filename}", file=sys.stderr)
            success = False
            continue
        success &= compare_with_exceptions(
            baseline.read_text(encoding="utf-8"), actual, current_exceptions, filename
        )

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
