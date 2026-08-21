#!/usr/bin/env python3
"""Compile the direct-path consumer against the actual packaged Rust crate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def run(*arguments: str, cwd: Path = ROOT, capture: bool = False) -> str:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout if capture else ""


def package_version() -> str:
    metadata = json.loads(
        run("cargo", "metadata", "--format-version", "1", "--no-deps", capture=True)
    )
    manifest = (ROOT / "rookie-rs" / "Cargo.toml").resolve()
    package = next(
        package
        for package in metadata["packages"]
        if package["name"] == "rookie-cookies"
        and Path(package["manifest_path"]).resolve() == manifest
    )
    return package["version"]


def extract_package(archive: Path, destination: Path, version: str) -> Path:
    with tarfile.open(archive, "r:gz") as package:
        root = destination.resolve()
        for member in package.getmembers():
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                raise RuntimeError(f"unsafe package member: {member.name}")
        package.extractall(destination, filter="data")
    return destination / f"rookie-cookies-{version}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        help="consume this existing .crate archive instead of creating a new package",
    )
    args = parser.parse_args()
    version = package_version()
    if args.archive is None:
        run(
            "cargo",
            "package",
            "--package",
            "rookie-cookies",
            "--allow-dirty",
            "--no-verify",
            "--locked",
        )
        archive = ROOT / "target" / "package" / f"rookie-cookies-{version}.crate"
    else:
        archive = args.archive.resolve(strict=True)
        expected_name = f"rookie-cookies-{version}.crate"
        if archive.name != expected_name:
            parser.error(
                f"archive name must be {expected_name!r} for workspace version {version}, "
                f"got {archive.name!r}"
            )
    with tempfile.TemporaryDirectory(prefix="rookie-packaged-consumer-") as temporary:
        temporary_path = Path(temporary)
        packaged_crate = extract_package(archive, temporary_path / "package", version)
        consumer = temporary_path / "consumer"
        (consumer / "src/bin").mkdir(parents=True)
        shutil.copy2(ROOT / "tests/direct_path_consumer/src/main.rs", consumer / "src/main.rs")
        (consumer / "src/bin/sqlite_inventory.rs").write_text(
            """\
use std::ffi::CStr;

fn main() {
    assert_eq!(rusqlite::version(), "3.53.2");
    let source_id = unsafe { CStr::from_ptr(rusqlite::ffi::sqlite3_sourceid()) };
    assert_eq!(
        source_id.to_str().expect("SQLite source ID is UTF-8"),
        "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24",
    );
}
""",
            encoding="utf-8",
        )
        manifest = f"""\
[package]
name = "packaged-direct-path-consumer"
version = "0.0.0"
edition = "2021"

[workspace]

[dependencies]
rookie-cookies = {{ path = {json.dumps(str(packaged_crate))}, default-features = false }}
rusqlite = {{ version = "=0.40.2", default-features = false, features = ["bundled", "fallible_uint"] }}
"""
        (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")

        metadata = json.loads(
            run(
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--manifest-path",
                str(consumer / "Cargo.toml"),
                cwd=consumer,
                capture=True,
            )
        )
        packages = metadata["packages"]
        sqlite_packages = [package for package in packages if package["name"] == "libsqlite3-sys"]
        if len(sqlite_packages) != 1 or sqlite_packages[0]["version"] != "0.38.2":
            raise RuntimeError(f"unexpected libsqlite3-sys resolution: {sqlite_packages}")
        rookie = next(package for package in packages if package["name"] == "rookie-cookies")
        direct_sqlite = next(
            dependency for dependency in rookie["dependencies"] if dependency["name"] == "libsqlite3-sys"
        )
        if direct_sqlite["req"] != "=0.38.2" or "bundled" not in direct_sqlite["features"]:
            raise RuntimeError(f"packaged SQLite constraint drifted: {direct_sqlite}")
        sqlite_id = sqlite_packages[0]["id"]
        sqlite_node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == sqlite_id)
        if "bundled" not in sqlite_node["features"]:
            raise RuntimeError(f"bundled SQLite feature is absent: {sqlite_node['features']}")

        run(
            "cargo",
            "check",
            "--locked",
            "--manifest-path",
            str(consumer / "Cargo.toml"),
            cwd=consumer,
        )
        run(
            "cargo",
            "run",
            "--locked",
            "--bin",
            "sqlite_inventory",
            "--manifest-path",
            str(consumer / "Cargo.toml"),
            cwd=consumer,
        )


if __name__ == "__main__":
    main()
