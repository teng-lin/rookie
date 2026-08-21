#!/usr/bin/env python3
"""Independently validate release versions and canonical package metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("check-release.py requires Python 3.11 or newer") from error

sys.path.insert(0, str(Path(__file__).resolve().parent))
import platform_contract  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_REPOSITORY = "https://github.com/teng-lin/rookie-cookies"
PYTHON_DOCUMENTATION = f"{CANONICAL_REPOSITORY}/blob/main/bindings/python/README.md"
ISSUE_TRACKER = f"{CANONICAL_REPOSITORY}/issues"
NODE_ENGINE_RANGE = ">=22"
RUST_MSRV = "1.88"
RUST_CATEGORIES = ["authentication", "os", "web-programming"]
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
SRI_INTEGRITY_PATTERN = re.compile(r"^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$")
# The npm native platform-package set now has exactly one source of truth:
# release/platform-contract.json. See scripts/platform_contract.py.
NATIVE_PACKAGES = platform_contract.npm_native_packages(platform_contract.load_contract())
RUST_PACKAGES = (
    ("rookie-rs/Cargo.toml", "rookie-cookies"),
    ("cli/Cargo.toml", "rookie-cookies-cli"),
    ("bindings/python/Cargo.toml", "rookie-cookies-python"),
    ("bindings/node/Cargo.toml", "rookie-cookies-node"),
)
RUST_VERSION_MANIFESTS = tuple(path for path, _package in RUST_PACKAGES) + (
    "xtask/Cargo.toml",
)


def load_json(relative_path: str) -> dict[str, Any]:
    with (ROOT / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_toml(relative_path: str) -> dict[str, Any]:
    with (ROOT / relative_path).open("rb") as handle:
        return tomllib.load(handle)


def is_semver(version: str) -> bool:
    match = SEMVER_PATTERN.fullmatch(version)
    if match is None:
        return False
    prerelease = match.group(4)
    return prerelease is None or all(
        not (identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"))
        for identifier in prerelease.split(".")
    )


def semver_precedence_key(version: str) -> tuple[Any, ...]:
    """A key such that comparing two SemVer strings' keys matches SemVer precedence."""
    match = SEMVER_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError(f"not a SemVer version: {version!r}")
    major, minor, patch, prerelease, _build = match.groups()
    core = (int(major), int(minor), int(patch))
    if prerelease is None:
        return (core, (1,))
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part) for part in prerelease.split(".")
    )
    return (core, (0, identifiers))


def latest_published_version(root: Path, *, excluding: str) -> str | None:
    """The highest SemVer-precedence `v*` tag in `root`, other than `v{excluding}`.

    `excluding` is the version being released: its own tag, if the release
    workflow already created it before this check runs, must not count as a
    "previously published" version to compare against.
    """
    result = subprocess.run(
        ["git", "tag", "--list", "v*"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    versions = [
        tag[1:]
        for tag in (line.strip() for line in result.stdout.splitlines())
        if tag.startswith("v") and is_semver(tag[1:]) and tag[1:] != excluding
    ]
    if not versions:
        return None
    return max(versions, key=semver_precedence_key)


def inherited_package_version(manifest: dict[str, Any]) -> bool:
    return manifest.get("package", {}).get("version") == {"workspace": True}


def inherited_rust_version(manifest: dict[str, Any]) -> bool:
    return manifest.get("package", {}).get("rust-version") == {"workspace": True}


def section_body(document: str, heading_end: int) -> str:
    next_heading = re.search(r"^## ", document[heading_end:], flags=re.MULTILINE)
    end = heading_end + next_heading.start() if next_heading else len(document)
    return document[heading_end:end]


def inherited_dependency(
    specification: Any, expected_features: list[str] | None = None
) -> bool:
    if not isinstance(specification, dict) or specification.get("workspace") is not True:
        return False
    if any(key in specification for key in ("version", "path", "git", "registry", "package")):
        return False
    features = specification.get("features", [])
    return sorted(features) == sorted(expected_features or [])


def cargo_lock_versions(lockfile: dict[str, Any], package_name: str) -> list[str]:
    return [
        package["version"]
        for package in lockfile.get("package", [])
        if package.get("name") == package_name and "source" not in package
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "version",
        nargs="?",
        help="expected release version (default: workspace.package.version)",
    )
    args = parser.parse_args()

    workspace = load_toml("Cargo.toml")
    workspace_version = workspace["workspace"]["package"]["version"]
    expected = args.version or workspace_version
    if not isinstance(expected, str) or not is_semver(expected):
        parser.error(f"invalid SemVer release version: {expected!r}")

    core = load_toml("rookie-rs/Cargo.toml")
    cli = load_toml("cli/Cargo.toml")
    python = load_toml("bindings/python/Cargo.toml")
    pyproject = load_toml("bindings/python/pyproject.toml")
    node = load_toml("bindings/node/Cargo.toml")
    rust_example = load_toml("examples/rust/http/Cargo.toml")
    cargo_lock = load_toml("Cargo.lock")
    node_package = load_json("bindings/node/package.json")
    node_lock = load_json("bindings/node/package-lock.json")
    javascript_lock = load_json("examples/javascript/package-lock.json")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    metadata: list[tuple[str, Any, Any]] = [
        (
            "Cargo.toml workspace Rust MSRV",
            workspace["workspace"]["package"].get("rust-version"),
            RUST_MSRV,
        ),
        ("rookie-rs/Cargo.toml package name", core["package"]["name"], "rookie-cookies"),
        (
            "rookie-rs/Cargo.toml categories",
            core["package"].get("categories"),
            RUST_CATEGORIES,
        ),
        ("rookie-rs/Cargo.toml repository", core["package"]["repository"], CANONICAL_REPOSITORY),
        ("bindings/python pyproject package name", pyproject["project"]["name"], "rookie-cookies"),
        ("bindings/python pyproject readme", pyproject["project"].get("readme"), "README.md"),
        (
            "bindings/python pyproject Python requirement",
            pyproject["project"].get("requires-python"),
            ">=3.11",
        ),
        (
            "bindings/python PyO3 ABI features",
            python["dependencies"]["pyo3"].get("features"),
            ["abi3-py311", "anyhow"],
        ),
        (
            "bindings/python supported Python classifiers",
            [
                classifier
                for classifier in pyproject["project"].get("classifiers", [])
                if classifier.startswith("Programming Language :: Python")
            ],
            [
                "Programming Language :: Python",
                "Programming Language :: Python :: 3 :: Only",
                "Programming Language :: Python :: 3.11",
                "Programming Language :: Python :: 3.12",
                "Programming Language :: Python :: 3.13",
                "Programming Language :: Python :: 3.14",
                "Programming Language :: Python :: Implementation :: CPython",
            ],
        ),
        (
            "bindings/python pyproject homepage",
            pyproject["project"]["urls"]["Homepage"],
            CANONICAL_REPOSITORY,
        ),
        (
            "bindings/python pyproject repository",
            pyproject["project"]["urls"]["Repository"],
            CANONICAL_REPOSITORY,
        ),
        (
            "bindings/python pyproject documentation",
            pyproject["project"]["urls"]["Documentation"],
            PYTHON_DOCUMENTATION,
        ),
        (
            "bindings/python pyproject issues",
            pyproject["project"]["urls"]["Issues"],
            ISSUE_TRACKER,
        ),
        ("bindings/node/package.json package name", node_package["name"], "rookie-cookies"),
        ("bindings/node/package.json repository", node_package["repository"], CANONICAL_REPOSITORY),
        (
            "workspace rookie-cookies dependency path",
            workspace["workspace"]["dependencies"]["rookie-cookies"].get("path"),
            "rookie-rs",
        ),
        (
            "workspace rookie-cookies dependency default-features",
            workspace["workspace"]["dependencies"]["rookie-cookies"].get("default-features"),
            False,
        ),
        (
            "bindings/node/package.json Node.js engine",
            node_package["engines"]["node"],
            NODE_ENGINE_RANGE,
        ),
        (
            "bindings/node/package-lock.json root Node.js engine",
            node_lock["packages"][""]["engines"]["node"],
            NODE_ENGINE_RANGE,
        ),
        (
            "examples/javascript/package-lock.json linked Node.js engine",
            javascript_lock["packages"]["../../bindings/node"]["engines"]["node"],
            NODE_ENGINE_RANGE,
        ),
    ]
    versions: list[tuple[str, Any]] = [
        ("Cargo.toml workspace package", workspace_version),
        (
            "Cargo.toml workspace rookie-cookies dependency",
            workspace["workspace"]["dependencies"]["rookie-cookies"]["version"],
        ),
        ("bindings/node/package.json", node_package["version"]),
        ("bindings/node/package-lock.json", node_lock["version"]),
        ("bindings/node/package-lock.json root package", node_lock["packages"][""]["version"]),
        (
            "examples/javascript/package-lock.json linked package",
            javascript_lock["packages"]["../../bindings/node"]["version"],
        ),
    ]

    failures: list[str] = []
    failures.extend(platform_contract.validate_npm_repository(platform_contract.load_contract()))

    previous = latest_published_version(ROOT, excluding=expected)
    if previous is not None and semver_precedence_key(expected) <= semver_precedence_key(previous):
        failures.append(
            f"release version {expected} does not exceed the latest published version "
            f"{previous} (v* tag); a release must strictly increase SemVer precedence"
        )

    for manifest_path, package_name in RUST_PACKAGES:
        manifest = load_toml(manifest_path)
        if not inherited_package_version(manifest):
            failures.append(
                f"{manifest_path}: package.version must inherit workspace.package.version"
            )
        lock_versions = cargo_lock_versions(cargo_lock, package_name)
        if lock_versions != [expected]:
            failures.append(
                f"Cargo.lock {package_name}: expected one local package at {expected}, found {lock_versions}"
            )

    for manifest_path in RUST_VERSION_MANIFESTS:
        if not inherited_rust_version(load_toml(manifest_path)):
            failures.append(
                f"{manifest_path}: package.rust-version must inherit workspace.package.rust-version"
            )

    dependency_specs = (
        ("cli/Cargo.toml rookie-cookies dependency", cli["dependencies"]["rookie-cookies"], []),
        (
            "bindings/python/Cargo.toml Unix rookie-cookies dependency",
            python["target"]["cfg(unix)"]["dependencies"]["rookie-cookies"],
            [],
        ),
        (
            "bindings/python/Cargo.toml Windows rookie-cookies dependency",
            python["target"]["cfg(windows)"]["dependencies"]["rookie-cookies"],
            ["appbound"],
        ),
        (
            "bindings/node/Cargo.toml Unix rookie-cookies dependency",
            node["target"]["cfg(unix)"]["dependencies"]["rookie-cookies"],
            [],
        ),
        (
            "bindings/node/Cargo.toml Windows rookie-cookies dependency",
            node["target"]["cfg(windows)"]["dependencies"]["rookie-cookies"],
            ["appbound"],
        ),
    )
    for label, specification, features in dependency_specs:
        if not inherited_dependency(specification, features):
            failures.append(
                f"{label}: must inherit the workspace dependency with features {features}"
            )

    rust_example_dependency = rust_example["dependencies"]["rookie-cookies"]
    if rust_example_dependency.get("path") != "../../../rookie-rs":
        failures.append("examples/rust/http/Cargo.toml: rookie-cookies path is not canonical")
    if "version" in rust_example_dependency:
        failures.append(
            "examples/rust/http/Cargo.toml: excluded path dependency must not carry a version"
        )
    for package_name in NATIVE_PACKAGES:
        package_path = (
            f"bindings/node/npm/{package_name.removeprefix('rookie-cookies-')}/package.json"
        )
        package = load_json(package_path)
        versions.extend(
            (
                (f"{package_path} package", package["version"]),
                (
                    f"bindings/node/package.json optional dependency {package_name}",
                    node_package["optionalDependencies"][package_name],
                ),
                (
                    f"bindings/node/package-lock.json optional dependency {package_name}",
                    node_lock["packages"][""]["optionalDependencies"][package_name],
                ),
                (
                    f"examples/javascript/package-lock.json optional dependency {package_name}",
                    javascript_lock["packages"]["../../bindings/node"][
                        "optionalDependencies"
                    ][package_name],
                ),
            )
        )
        lock_record = node_lock["packages"].get(f"node_modules/{package_name}")
        if lock_record is None:
            failures.append(
                f"bindings/node/package-lock.json: missing package record {package_name}"
            )
        else:
            versions.append(
                (
                    f"bindings/node/package-lock.json package record {package_name}",
                    lock_record["version"],
                )
            )
            if lock_record.get("optional") is not True:
                failures.append(
                    f"bindings/node/package-lock.json package record {package_name}: must remain optional"
                )
            has_resolved = "resolved" in lock_record
            has_integrity = "integrity" in lock_record
            if has_resolved != has_integrity:
                failures.append(
                    f"bindings/node/package-lock.json package record {package_name}: "
                    "resolved and integrity must be set or absent together, not just one"
                )
            elif has_integrity and not SRI_INTEGRITY_PATTERN.fullmatch(lock_record["integrity"]):
                failures.append(
                    f"bindings/node/package-lock.json package record {package_name}: "
                    f"integrity {lock_record['integrity']!r} is not a well-formed SRI hash"
                )
        metadata.extend(
            (
                (f"{package_path} repository", package["repository"], CANONICAL_REPOSITORY),
                (f"{package_path} package name", package["name"], package_name),
                (
                    f"{package_path} Node.js engine",
                    package["engines"]["node"],
                    NODE_ENGINE_RANGE,
                ),
            )
        )

    failures.extend(
        f"{label}: expected {expected}, found {actual}"
        for label, actual in versions
        if actual != expected
    )
    failures.extend(
        f"{label}: expected {expected_value}, found {actual}"
        for label, actual, expected_value in metadata
        if actual != expected_value
    )
    release_matches = list(
        re.finditer(
            rf"^## \[{re.escape(expected)}\] - (\d{{4}}-\d{{2}}-\d{{2}})[ \t]*$",
            changelog,
            flags=re.MULTILINE,
        )
    )
    if len(release_matches) != 1:
        failures.append(
            f"CHANGELOG.md: expected exactly one dated {expected} release heading, found {len(release_matches)}"
        )
    else:
        release_date = release_matches[0].group(1)
        try:
            parsed_release_date = date.fromisoformat(release_date)
        except ValueError:
            parsed_release_date = None
        if parsed_release_date is None or parsed_release_date.isoformat() != release_date:
            failures.append(
                f"CHANGELOG.md: release {expected} has invalid date {release_date!r}"
            )
        if not section_body(changelog, release_matches[0].end()).strip():
            failures.append(f"CHANGELOG.md: release {expected} has no release-note prose")
    unreleased_headings = re.findall(
        r"^## \[Unreleased\][ \t]*$", changelog, flags=re.MULTILINE
    )
    if len(unreleased_headings) != 1:
        failures.append(
            f"CHANGELOG.md: expected exactly one Unreleased heading, found {len(unreleased_headings)}"
        )

    if failures:
        print("Release metadata is inconsistent:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    source = "explicit version" if args.version else "workspace.package.version"
    print(f"Release metadata is consistent for rookie-cookies {expected} ({source}).")
    return 0


if __name__ == "__main__":
    try:
        result = main()
    except (OSError, KeyError, TypeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"Release metadata is malformed: {error}", file=sys.stderr)
        result = 1
    raise SystemExit(result)
