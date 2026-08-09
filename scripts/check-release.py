#!/usr/bin/env python3
"""Validate release versions and canonical package metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
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
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
NATIVE_PACKAGES = (
    "rookie-cookies-darwin-arm64",
    "rookie-cookies-darwin-x64",
    "rookie-cookies-linux-x64-gnu",
    "rookie-cookies-win32-x64-msvc",
)


def load_json(relative_path: str) -> dict[str, Any]:
    with (ROOT / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def load_toml(relative_path: str) -> dict[str, Any]:
    with (ROOT / relative_path).open("rb") as handle:
        return tomllib.load(handle)


def target_dependency_versions(
    manifest: dict[str, Any], dependency: str
) -> list[tuple[str, str]]:
    versions: list[tuple[str, str]] = []
    for target, table in manifest.get("target", {}).items():
        dependencies = table.get("dependencies", {})
        if dependency in dependencies:
            versions.append((target, dependencies[dependency]["version"]))
    return versions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="expected release version, for example 0.5.7")
    args = parser.parse_args()

    expected = args.version
    if not VERSION_PATTERN.fullmatch(expected):
        parser.error(f"invalid release version: {expected!r}")

    core = load_toml("rookie-rs/Cargo.toml")
    cli = load_toml("cli/Cargo.toml")
    python = load_toml("bindings/python/Cargo.toml")
    pyproject = load_toml("bindings/python/pyproject.toml")
    node = load_toml("bindings/node/Cargo.toml")
    rust_example = load_toml("examples/rust/http/Cargo.toml")
    config = load_json("rookie-rs/config.json")
    node_package = load_json("bindings/node/package.json")
    node_lock = load_json("bindings/node/package-lock.json")
    javascript_lock = load_json("examples/javascript/package-lock.json")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    metadata: list[tuple[str, str, str]] = [
        (
            "rookie-rs/Cargo.toml package name",
            core["package"]["name"],
            "rookie-cookies",
        ),
        ("rookie-rs/Cargo.toml", core["package"]["repository"], CANONICAL_REPOSITORY),
        (
            "bindings/python pyproject package name",
            pyproject["project"]["name"],
            "rookie-cookies",
        ),
        (
            "bindings/python pyproject readme",
            pyproject["project"].get("readme"),
            "README.md",
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
        (
            "bindings/node/package.json package name",
            node_package["name"],
            "rookie-cookies",
        ),
        (
            "bindings/node/package.json",
            node_package["repository"],
            CANONICAL_REPOSITORY,
        ),
    ]
    versions: list[tuple[str, str]] = [
        ("rookie-rs/Cargo.toml package", core["package"]["version"]),
        ("rookie-rs/config.json", config["version"]),
        ("cli/Cargo.toml package", cli["package"]["version"]),
        (
            "cli/Cargo.toml rookie-cookies dependency",
            cli["dependencies"]["rookie-cookies"]["version"],
        ),
        ("bindings/python/Cargo.toml package", python["package"]["version"]),
        ("bindings/node/Cargo.toml package", node["package"]["version"]),
        ("bindings/node/package.json", node_package["version"]),
        ("bindings/node/package-lock.json", node_lock["version"]),
        (
            "bindings/node/package-lock.json root package",
            node_lock["packages"][""]["version"],
        ),
        (
            "examples/rust/http/Cargo.toml rookie-cookies dependency",
            rust_example["dependencies"]["rookie-cookies"]["version"],
        ),
        (
            "examples/javascript/package-lock.json linked package",
            javascript_lock["packages"]["../../bindings/node"]["version"],
        ),
    ]
    for package_name in NATIVE_PACKAGES:
        package_path = f"bindings/node/npm/{package_name.removeprefix('rookie-cookies-')}/package.json"
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
                    f"bindings/node/package-lock.json package record {package_name}",
                    node_lock["packages"][f"node_modules/{package_name}"]["version"],
                ),
                (
                    f"examples/javascript/package-lock.json optional dependency {package_name}",
                    javascript_lock["packages"]["../../bindings/node"][
                        "optionalDependencies"
                    ][package_name],
                ),
            )
        )
        metadata.extend(
            (
                (package_path, package["repository"], CANONICAL_REPOSITORY),
                (f"{package_path} package name", package["name"], package_name),
            )
        )
    versions.extend(
        (
            f"bindings/python/Cargo.toml {target} rookie-core dependency",
            version,
        )
        for target, version in target_dependency_versions(python, "rookie-core")
    )
    versions.extend(
        (
            f"bindings/node/Cargo.toml {target} rookie-cookies dependency",
            version,
        )
        for target, version in target_dependency_versions(node, "rookie-cookies")
    )

    failures = [
        f"{label}: expected {expected}, found {actual}"
        for label, actual in versions
        if actual != expected
    ]
    failures.extend(
        f"{label}: expected {expected_value}, found {actual}"
        for label, actual, expected_value in metadata
        if actual != expected_value
    )
    if f"## [{expected}]" not in changelog:
        failures.append(f"CHANGELOG.md: missing a {expected} release section")

    if failures:
        print("Release metadata is inconsistent:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Release metadata is consistent for rookie-cookies {expected}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
