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
DEPRECATION_CONTRACT = "deprecated-items.json"


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


def render_rustdoc_json(repo: Path, feature_args: list[str]) -> dict[str, object]:
    """Build rustdoc JSON because cargo-public-api omits deprecation metadata."""
    command = [
        "cargo",
        f"+{NIGHTLY}",
        "rustdoc",
        "--manifest-path",
        str(repo / "rookie-rs" / "Cargo.toml"),
        "--target-dir",
        str(repo / "target"),
        "--lib",
        "--locked",
        *feature_args,
        "--",
        "-Z",
        "unstable-options",
        "--output-format",
        "json",
    ]
    try:
        subprocess.run(command, check=True, text=True, capture_output=True, cwd=repo)
        return json.loads((repo / "target" / "doc" / "rookie_cookies.json").read_text())
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            diagnostic = (error.stderr or error.stdout or str(error)).strip()
        else:
            diagnostic = str(error)
        raise PublicApiCommandError(diagnostic) from None


def load_deprecation_contract(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 2 or not isinstance(data.get("deprecated"), list):
        raise ValueError(f"invalid deprecation contract in {path}")

    required = {"path", "since", "note", "platforms", "feature_sets"}
    seen: set[tuple[str, str, str]] = set()
    for item in data["deprecated"]:
        if not isinstance(item, dict) or set(item) != required or not all(
            isinstance(item[field], str) and item[field].strip()
            for field in ("path", "since", "note")
        ):
            raise ValueError(
                f"deprecated API item has invalid fields: {item!r}"
            )
        platforms = item["platforms"]
        feature_sets = item["feature_sets"]
        if (
            not isinstance(platforms, list)
            or not platforms
            or not all(isinstance(platform, str) and platform in PLATFORMS for platform in platforms)
            or len(platforms) != len(set(platforms))
        ):
            raise ValueError(f"invalid deprecation platforms: {item!r}")
        if (
            not isinstance(feature_sets, list)
            or not feature_sets
            or not all(
                isinstance(feature_set, str) and feature_set in FEATURE_SETS
                for feature_set in feature_sets
            )
            or len(feature_sets) != len(set(feature_sets))
        ):
            raise ValueError(f"invalid deprecation feature sets: {item!r}")
        for platform in platforms:
            for feature_set in feature_sets:
                key = (platform, feature_set, item["path"])
                if key in seen:
                    raise ValueError(f"duplicate scoped deprecated API path: {key!r}")
                seen.add(key)
    return data["deprecated"]


def scoped_deprecations(
    contract: list[dict[str, object]], platform: str, feature_set: str
) -> list[dict[str, str]]:
    return [
        {"path": item["path"], "since": item["since"], "note": item["note"]}
        for item in contract
        if platform in item["platforms"] and feature_set in item["feature_sets"]
    ]


def check_deprecation_contract(
    rustdoc: dict[str, object], expected: list[dict[str, str]], label: str
) -> bool:
    """Require the complete scoped deprecated set and its exact metadata."""
    index = rustdoc.get("index")
    paths = rustdoc.get("paths")
    if not isinstance(index, dict) or not isinstance(paths, dict):
        print(f"invalid rustdoc JSON structure for {label}", file=sys.stderr)
        return False

    actual: dict[str, object] = {}
    for item_id, item in index.items():
        if (
            not isinstance(item, dict)
            or item.get("crate_id") != 0
            or item.get("visibility") != "public"
        ):
            continue
        path = paths.get(str(item_id))
        if not isinstance(path, dict) or not isinstance(path.get("path"), list):
            continue
        deprecation = item.get("deprecation")
        if deprecation is not None:
            actual["::".join(path["path"])] = deprecation

    wanted = {
        item["path"]: {"since": item["since"], "note": item["note"]} for item in expected
    }
    success = True
    for path in sorted(wanted.keys() | actual.keys()):
        if path not in wanted:
            print(f"unexpected deprecated API item in {label}: {path}", file=sys.stderr)
            success = False
        elif path not in actual:
            print(f"missing deprecated API item in {label}: {path}", file=sys.stderr)
            success = False
        elif actual[path] != wanted[path]:
            print(
                f"deprecation contract mismatch for {path} in {label}: "
                f"expected {wanted[path]!r}, got {actual[path]!r}",
                file=sys.stderr,
            )
            success = False
    return success


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
    allowed = {(exception["change"], exception["item"]) for exception in exceptions}

    stale = [
        exception
        for exception in exceptions
        if exception["change"] != "missing-baseline"
        and (
            (
                exception["change"] == "added"
                and actual_lines.count(exception["item"])
                <= expected_lines.count(exception["item"])
            )
            or (
                exception["change"] == "removed"
                and expected_lines.count(exception["item"])
                <= actual_lines.count(exception["item"])
            )
        )
    ]
    if stale:
        print(f"stale or mismatched public API exceptions for {label}: {stale!r}", file=sys.stderr)
        return False

    previous = [False] * (len(actual_lines) + 1)
    previous[0] = True
    for actual_index, actual_item in enumerate(actual_lines, start=1):
        previous[actual_index] = (
            previous[actual_index - 1] and ("added", actual_item) in allowed
        )

    for expected_item in expected_lines:
        current = [False] * (len(actual_lines) + 1)
        current[0] = previous[0] and ("removed", expected_item) in allowed
        for actual_index, actual_item in enumerate(actual_lines, start=1):
            current[actual_index] = (
                (previous[actual_index - 1] and expected_item == actual_item)
                or (previous[actual_index] and ("removed", expected_item) in allowed)
                or (current[actual_index - 1] and ("added", actual_item) in allowed)
            )
        previous = current

    if previous[-1]:
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
    deprecation_file = baseline_dir / DEPRECATION_CONTRACT

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
        deprecation_contract = load_deprecation_contract(deprecation_file)
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
        try:
            rustdoc = render_rustdoc_json(repo, feature_args)
        except PublicApiCommandError as error:
            print(f"rustdoc JSON failed for {filename}: {error}", file=sys.stderr)
            return 2
        success &= check_deprecation_contract(
            rustdoc,
            scoped_deprecations(deprecation_contract, args.platform, feature_set),
            filename,
        )

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
