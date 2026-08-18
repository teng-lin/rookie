#!/usr/bin/env python3
"""Pack the npm root and native packages using the release workflow contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


def npm_pack(npm: str, package: Path, output: Path, *, cwd: Path) -> Path:
    result = subprocess.run(
        [
            npm,
            "pack",
            str(package),
            "--pack-destination",
            str(output),
            "--ignore-scripts",
            "--json",
        ],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )
    payload = json.loads(result.stdout)
    if len(payload) != 1 or not payload[0].get("filename"):
        raise RuntimeError(f"unexpected npm pack output: {result.stdout}")
    tarball = output / payload[0]["filename"]
    if not tarball.is_file():
        raise RuntimeError(f"npm did not create {tarball}")
    return tarball


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-root", type=Path, default=Path("bindings/node"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--platform",
        action="append",
        dest="platforms",
        help="native npm directory to pack; defaults to every checked-in platform",
    )
    args = parser.parse_args()

    npm = shutil.which("npm")
    if npm is None:
        parser.error("npm was not found on PATH")
    node_root = args.node_root.resolve()
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("sync-node-license.py")),
            "--node-root",
            str(node_root),
        ],
        check=True,
    )
    npm_root = node_root / "npm"
    platforms = args.platforms or sorted(
        path.name for path in npm_root.iterdir() if (path / "package.json").is_file()
    )
    if len(platforms) != len(set(platforms)):
        parser.error(f"duplicate platforms requested: {platforms}")

    packages: list[Path] = []
    for platform in platforms:
        package = npm_root / platform
        metadata_path = package / "package.json"
        if not metadata_path.is_file():
            parser.error(f"native package metadata is missing: {metadata_path}")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        native_entry = metadata.get("main")
        if not isinstance(native_entry, str) or not native_entry.endswith(".node"):
            parser.error(f"invalid native package main entry: {metadata}")
        binary = package / native_entry
        if not binary.is_file() or binary.stat().st_size == 0:
            parser.error(f"native package binary is missing or empty: {binary}")
        packages.append(package)

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    existing = sorted(output.glob("*.tgz"))
    if existing:
        parser.error(f"output already contains npm tarballs: {existing}")
    tarballs = [npm_pack(npm, package, output, cwd=node_root) for package in packages]
    tarballs.append(npm_pack(npm, node_root, output, cwd=node_root))
    if len(list(output.glob("*.tgz"))) != len(packages) + 1:
        raise RuntimeError("npm output count does not match native packages plus root")
    print(json.dumps([str(path) for path in tarballs], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
