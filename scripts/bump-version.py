#!/usr/bin/env python3
"""Bump every release metadata mirror from one structurally addressed version."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("bump-version.py requires Python 3.11 or newer") from error

sys.path.insert(0, str(Path(__file__).resolve().parent))
import platform_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
# The npm native platform-package set now has exactly one source of truth:
# release/platform-contract.json. See scripts/platform_contract.py.
NATIVE_PACKAGES = platform_contract.npm_native_packages(platform_contract.load_contract())
NATIVE_MANIFESTS = tuple(
    Path("bindings/node/npm")
    / package_name.removeprefix("rookie-cookies-")
    / "package.json"
    for package_name in NATIVE_PACKAGES
)
MANAGED_PATHS = (
    Path("Cargo.toml"),
    Path("Cargo.lock"),
    Path("CHANGELOG.md"),
    Path("bindings/node/package.json"),
    *NATIVE_MANIFESTS,
    Path("bindings/node/package-lock.json"),
    Path("examples/javascript/package-lock.json"),
)
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


class ReleaseError(RuntimeError):
    """An expected release-preparation failure with an actionable message."""


@dataclass(frozen=True)
class FieldChange:
    path: Path
    field: str
    before: str
    after: str


def validate_semver(version: str) -> str:
    match = SEMVER_PATTERN.fullmatch(version)
    if match is None:
        raise ReleaseError(f"invalid SemVer release version: {version!r}")
    prerelease = match.group(4)
    if prerelease is not None:
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                raise ReleaseError(
                    f"invalid SemVer release version (numeric pre-release identifier has a leading zero): {version!r}"
                )
    return version


def validate_date(value: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ReleaseError(f"invalid release date (expected YYYY-MM-DD): {value!r}") from error
    if parsed.isoformat() != value:
        raise ReleaseError(f"invalid release date (expected YYYY-MM-DD): {value!r}")
    return value


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError(f"cannot parse {path}: {error}") from error


def nested_value(document: dict[str, Any], keys: Sequence[str], path: Path) -> Any:
    value: Any = document
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            dotted = ".".join(keys)
            raise ReleaseError(f"{path}: missing TOML field {dotted}")
        value = value[key]
    return value


def update_toml_string(
    path: Path, table: Sequence[str], key: str, new_value: str
) -> FieldChange | None:
    """Update one parsed TOML string while preserving the rest of the document."""
    document = load_toml(path)
    old_value = nested_value(document, (*table, key), path)
    if not isinstance(old_value, str):
        raise ReleaseError(f"{path}: {'.'.join((*table, key))} must be a string")
    if old_value == new_value:
        return None

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    header = f"[{'.'.join(table)}]"
    table_starts = [
        index for index, line in enumerate(lines) if line.strip() == header
    ]
    if len(table_starts) != 1:
        raise ReleaseError(
            f"{path}: expected exactly one {header} table, found {len(table_starts)}"
        )
    start = table_starts[0] + 1
    end = next(
        (
            index
            for index in range(start, len(lines))
            if lines[index].lstrip().startswith("[")
        ),
        len(lines),
    )
    key_pattern = re.compile(
        rf'^(?P<prefix>\s*{re.escape(key)}\s*=\s*)"(?P<value>[^"]*)"(?P<suffix>\s*(?:#.*)?)(?P<newline>\r?\n)?$'
    )
    matches = [
        (index, key_pattern.fullmatch(lines[index])) for index in range(start, end)
    ]
    matches = [(index, match) for index, match in matches if match is not None]
    if len(matches) != 1:
        raise ReleaseError(
            f"{path}: expected exactly one {key!r} string in {header}, found {len(matches)}"
        )
    index, match = matches[0]
    assert match is not None
    lines[index] = (
        f'{match.group("prefix")}"{new_value}"{match.group("suffix")}'
        f'{match.group("newline") or ""}'
    )
    updated = "".join(lines)
    try:
        parsed = tomllib.loads(updated)
    except tomllib.TOMLDecodeError as error:
        raise ReleaseError(f"{path}: generated invalid TOML: {error}") from error
    if nested_value(parsed, (*table, key), path) != new_value:
        raise ReleaseError(f"{path}: failed to update {'.'.join((*table, key))}")
    path.write_text(updated, encoding="utf-8")
    return FieldChange(path, ".".join((*table, key)), old_value, new_value)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReleaseError(f"{path}: expected a top-level JSON object")
    return value


def update_json_strings(
    path: Path, updates: dict[tuple[str, ...], str]
) -> list[FieldChange]:
    document = load_json(path)
    changes: list[FieldChange] = []
    for keys, new_value in updates.items():
        parent: Any = document
        for key in keys[:-1]:
            if not isinstance(parent, dict) or key not in parent:
                raise ReleaseError(f"{path}: missing JSON field {'.'.join(keys)}")
            parent = parent[key]
        leaf = keys[-1]
        if not isinstance(parent, dict) or leaf not in parent:
            raise ReleaseError(f"{path}: missing JSON field {'.'.join(keys)}")
        old_value = parent[leaf]
        if not isinstance(old_value, str):
            raise ReleaseError(f"{path}: {'.'.join(keys)} must be a string")
        if old_value != new_value:
            parent[leaf] = new_value
            changes.append(FieldChange(path, ".".join(keys), old_value, new_value))
    if changes:
        path.write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return changes


def unreleased_body(changelog: str, heading_end: int) -> str:
    next_heading = re.search(r"^## ", changelog[heading_end:], flags=re.MULTILINE)
    end = heading_end + next_heading.start() if next_heading else len(changelog)
    return changelog[heading_end:end]


def update_changelog(
    path: Path,
    current_version: str,
    new_version: str,
    release_date: str,
    explicit_date: bool,
) -> FieldChange | None:
    changelog = path.read_text(encoding="utf-8")
    unreleased = list(
        re.finditer(r"^## \[Unreleased\][ \t]*$", changelog, flags=re.MULTILINE)
    )
    if len(unreleased) != 1:
        raise ReleaseError(
            f"{path}: expected exactly one '## [Unreleased]' section, found {len(unreleased)}"
        )
    release_pattern = re.compile(
        rf"^## \[{re.escape(new_version)}\](?: - (?P<date>\d{{4}}-\d{{2}}-\d{{2}}))?[ \t]*$",
        flags=re.MULTILINE,
    )
    releases = list(release_pattern.finditer(changelog))

    if current_version == new_version:
        if len(releases) != 1:
            raise ReleaseError(
                f"{path}: current version {new_version} requires exactly one existing release heading"
            )
        existing_date = releases[0].group("date")
        if existing_date is None:
            raise ReleaseError(
                f"{path}: release heading for {new_version} is missing its YYYY-MM-DD date"
            )
        if explicit_date and existing_date != release_date:
            raise ReleaseError(
                f"{path}: release {new_version} already uses {existing_date}, not {release_date}"
            )
        if unreleased_body(changelog, unreleased[0].end()).strip():
            raise ReleaseError(
                f"{path}: version {new_version} is already released but Unreleased contains new prose"
            )
        return None

    if releases:
        raise ReleaseError(f"{path}: release heading for {new_version} already exists")
    heading = unreleased[0]
    if not unreleased_body(changelog, heading.end()).strip():
        raise ReleaseError(
            f"{path}: Unreleased must contain release-note prose before preparing {new_version}"
        )
    replacement = f"## [Unreleased]\n\n## [{new_version}] - {release_date}"
    updated = changelog[: heading.start()] + replacement + changelog[heading.end() :]
    path.write_text(updated, encoding="utf-8")
    return FieldChange(
        path,
        "Unreleased heading",
        "## [Unreleased]",
        f"## [Unreleased] + ## [{new_version}] - {release_date}",
    )


def command_text(command: Sequence[str]) -> str:
    return shlex.join(command)


def run_command(command: Sequence[str], cwd: Path) -> None:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise ReleaseError(f"cannot run {command[0]!r}: {error}") from error
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        raise ReleaseError(
            f"command failed ({result.returncode}): {command_text(command)}\n{details}"
        )


def verify_release(root: Path, version: str) -> None:
    run_command((sys.executable, "scripts/check-release.py", version), root)


def normalize_native_lock_records(path: Path, version: str) -> None:
    """Add npm-ci placeholders for native versions that are not published yet.

    A record already carrying `resolved`/`integrity` for the *target* version
    (e.g. a real `npm install` already pinned this exact release's SRI hash)
    is left untouched instead of being overwritten with a bare placeholder —
    the previous unconditional overwrite silently stripped that SRI pin on
    every bump, including no-op re-runs where the version did not change.
    Only a record for a *different* version is replaced: no SHA can exist yet
    for content that has not been published.
    """
    lockfile = load_json(path)
    packages = lockfile.get("packages")
    if not isinstance(packages, dict) or "" not in packages:
        raise ReleaseError(f"{path}: missing lockfile package records")
    for package_name in NATIVE_PACKAGES:
        key = f"node_modules/{package_name}"
        existing = packages.get(key)
        if (
            isinstance(existing, dict)
            and existing.get("version") == version
            and "resolved" in existing
            and "integrity" in existing
        ):
            continue
        packages[key] = {
            "version": version,
            "optional": True,
        }
    lockfile["packages"] = {
        key: packages[key]
        for key in ([""] + sorted(key for key in packages if key))
    }
    path.write_text(
        json.dumps(lockfile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def regenerate_lockfiles(root: Path, version: str) -> None:
    run_command(("cargo", "update", "--workspace"), root)
    npm_command = (
        "npm",
        "install",
        "--package-lock-only",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
    )
    node_root = root / "bindings/node"
    javascript_example = root / "examples/javascript"
    run_command(npm_command, node_root)
    normalize_native_lock_records(node_root / "package-lock.json", version)
    run_command(npm_command, javascript_example)
    npm_ci_check = (
        "npm",
        "ci",
        "--ignore-scripts",
        "--dry-run",
        "--no-audit",
        "--no-fund",
    )
    run_command(npm_ci_check, node_root)
    run_command(npm_ci_check, javascript_example)


def snapshot_files(root: Path) -> dict[Path, bytes | None]:
    snapshot: dict[Path, bytes | None] = {}
    for relative in MANAGED_PATHS:
        path = root / relative
        try:
            snapshot[relative] = path.read_bytes() if path.exists() else None
        except OSError as error:
            raise ReleaseError(f"cannot snapshot {path}: {error}") from error
    return snapshot


def restore_files(root: Path, snapshot: dict[Path, bytes | None]) -> None:
    failures: list[str] = []
    for relative, contents in snapshot.items():
        path = root / relative
        try:
            if contents is None:
                if path.exists():
                    path.unlink()
            else:
                path.write_bytes(contents)
        except OSError as error:
            failures.append(f"{path}: {error}")
    if failures:
        raise ReleaseError("cannot restore release metadata:\n- " + "\n- ".join(failures))


def current_workspace_version(root: Path) -> str:
    manifest = load_toml(root / "Cargo.toml")
    version = nested_value(manifest, ("workspace", "package", "version"), root / "Cargo.toml")
    if not isinstance(version, str):
        raise ReleaseError("Cargo.toml: workspace.package.version must be a string")
    return validate_semver(version)


def bump_version(
    root: Path, new_version: str, release_date: str, explicit_date: bool
) -> list[FieldChange]:
    new_version = validate_semver(new_version)
    release_date = validate_date(release_date)
    current_version = current_workspace_version(root)
    verify_release(root, current_version)

    snapshot = snapshot_files(root)
    changes: list[FieldChange] = []
    try:
        for table in (
            ("workspace", "package"),
            ("workspace", "dependencies", "rookie-cookies"),
        ):
            change = update_toml_string(
                root / "Cargo.toml", table, "version", new_version
            )
            if change is not None:
                changes.append(change)

        root_package = root / "bindings/node/package.json"
        npm_updates = {("version",): new_version}
        npm_updates.update(
            {
                ("optionalDependencies", package_name): new_version
                for package_name in NATIVE_PACKAGES
            }
        )
        changes.extend(update_json_strings(root_package, npm_updates))
        for relative_path in NATIVE_MANIFESTS:
            changes.extend(
                update_json_strings(root / relative_path, {("version",): new_version})
            )

        changelog_change = update_changelog(
            root / "CHANGELOG.md",
            current_version,
            new_version,
            release_date,
            explicit_date,
        )
        if changelog_change is not None:
            changes.append(changelog_change)

        if changes:
            regenerate_lockfiles(root, new_version)
        verify_release(root, new_version)
    except (OSError, ReleaseError) as error:
        try:
            restore_files(root, snapshot)
        except ReleaseError as rollback_error:
            raise ReleaseError(
                f"release bump failed: {error}\nrollback also failed: {rollback_error}"
            ) from rollback_error
        raise ReleaseError(f"release bump rolled back: {error}") from error

    changed_files = []
    for relative, contents in snapshot.items():
        try:
            changed = (root / relative).read_bytes() != contents
        except OSError as error:
            raise ReleaseError(f"cannot inspect generated {root / relative}: {error}") from error
        if changed:
            changed_files.append(relative)
    print(f"Release metadata is consistent for rookie-cookies {new_version}.")
    if not changed_files:
        print("No files changed; the requested version is already prepared.")
        return changes

    print("Changed fields:")
    for change in changes:
        print(
            f"- {change.path.relative_to(root)}: {change.field}: "
            f"{change.before!r} -> {change.after!r}"
        )
    field_paths = {change.path.relative_to(root) for change in changes}
    for relative in changed_files:
        if relative not in field_paths:
            print(f"- {relative}: regenerated by release tooling")
    return changes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bump release metadata and regenerate Cargo/npm lockfiles."
    )
    parser.add_argument("version", help="new SemVer release version, for example 1.2.3")
    parser.add_argument(
        "--date",
        dest="release_date",
        help="release date in YYYY-MM-DD form (default: today's UTC date)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    explicit_date = args.release_date is not None
    release_date = args.release_date or datetime.now(timezone.utc).date().isoformat()
    try:
        bump_version(ROOT, args.version, release_date, explicit_date)
    except ReleaseError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
