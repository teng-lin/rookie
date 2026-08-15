#!/usr/bin/env python3
"""Independently validate release versions and canonical package metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("check-release.py requires Python 3.11 or newer") from error


ROOT = Path(__file__).resolve().parents[1]
CANONICAL_REPOSITORY = "https://github.com/teng-lin/rookie-cookies"
PYTHON_DOCUMENTATION = f"{CANONICAL_REPOSITORY}/blob/main/docs/Python.md"
ISSUE_TRACKER = f"{CANONICAL_REPOSITORY}/issues"
NODE_ENGINE_RANGE = ">=22"
SEMVER_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
NATIVE_PACKAGES = (
    "rookie-cookies-darwin-arm64",
    "rookie-cookies-darwin-x64",
    "rookie-cookies-linux-x64-gnu",
    "rookie-cookies-win32-x64-msvc",
)
RUST_PACKAGES = (
    ("rookie-rs/Cargo.toml", "rookie-cookies"),
    ("cli/Cargo.toml", "rookie-cookies-cli"),
    ("bindings/python/Cargo.toml", "rookie-cookies-python"),
    ("bindings/node/Cargo.toml", "rookie-cookies-node"),
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


def inherited_package_version(manifest: dict[str, Any]) -> bool:
    return manifest.get("package", {}).get("version") == {"workspace": True}


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
        ("rookie-rs/Cargo.toml package name", core["package"]["name"], "rookie-cookies"),
        ("rookie-rs/Cargo.toml repository", core["package"]["repository"], CANONICAL_REPOSITORY),
        ("bindings/python pyproject package name", pyproject["project"]["name"], "rookie-cookies"),
        ("bindings/python pyproject readme", pyproject["project"].get("readme"), "README.md"),
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
    release_headings = re.findall(
        rf"^## \[{re.escape(expected)}\] - (\d{{4}}-\d{{2}}-\d{{2}})[ \t]*$",
        changelog,
        flags=re.MULTILINE,
    )
    if len(release_headings) != 1:
        failures.append(
            f"CHANGELOG.md: expected exactly one dated {expected} release heading, found {len(release_headings)}"
        )
    else:
        try:
            parsed_release_date = date.fromisoformat(release_headings[0])
        except ValueError:
            parsed_release_date = None
        if parsed_release_date is None or parsed_release_date.isoformat() != release_headings[0]:
            failures.append(
                f"CHANGELOG.md: release {expected} has invalid date {release_headings[0]!r}"
            )
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
