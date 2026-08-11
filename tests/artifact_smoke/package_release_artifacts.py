#!/usr/bin/env python3
"""Assemble native release artifacts and record their exact provenance.

This intentionally mirrors the release shape instead of testing from the source
tree: one CLI executable, one Python wheel, and npm root + native tarballs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Rust target triple")
    parser.add_argument(
        "--npm-platform",
        required=True,
        help="napi-rs package directory, for example linux-x64-gnu",
    )
    parser.add_argument("--source-sha", required=True)
    parser.add_argument(
        "--output", type=Path, default=Path("target/artifact-smoke-release")
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def npm_command() -> str:
    command = shutil.which("npm")
    if command is None:
        raise RuntimeError("npm was not found on PATH")
    return command


def main() -> int:
    args = parse_args()
    repository = Path(__file__).resolve().parents[2]
    output = (repository / args.output).resolve()
    if output.exists():
        shutil.rmtree(output)
    cli_output = output / "cli"
    python_output = output / "python"
    npm_output = output / "npm"
    for directory in (cli_output, python_output, npm_output):
        directory.mkdir(parents=True)

    executable_suffix = ".exe" if os.name == "nt" else ""
    built_cli = (
        repository
        / "target"
        / args.target
        / "release"
        / f"rookie-cookies{executable_suffix}"
    )
    if not built_cli.is_file():
        raise RuntimeError(f"CLI build output is missing: {built_cli}")
    cli = cli_output / f"rookie-cookies-cli-{args.target}{executable_suffix}"
    shutil.copy2(built_cli, cli)

    wheels = sorted((repository / "bindings/python/dist").glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, found: {wheels}")
    wheel = python_output / wheels[0].name
    shutil.copy2(wheels[0], wheel)

    node_root = repository / "bindings/node"
    native_package = node_root / "npm" / args.npm_platform
    native_metadata = json.loads((native_package / "package.json").read_text())
    native_filename = native_metadata["main"]
    built_binding = node_root / native_filename
    if not built_binding.is_file():
        raise RuntimeError(f"Node build output is missing: {built_binding}")
    napi_artifacts = repository / "target/artifact-smoke-napi"
    if napi_artifacts.exists():
        shutil.rmtree(napi_artifacts)
    napi_artifacts.mkdir(parents=True)
    shutil.copy2(built_binding, napi_artifacts / native_filename)
    subprocess.run(
        [
            npm_command(),
            "run",
            "artifacts",
            "--",
            "--dir",
            str(napi_artifacts),
            "--dist",
            "npm",
        ],
        cwd=node_root,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(repository / "scripts/package-npm-tarballs.py"),
            "--node-root",
            str(node_root),
            "--output",
            str(npm_output),
            "--platform",
            args.npm_platform,
        ],
        cwd=repository,
        check=True,
    )
    npm_tarballs = sorted(npm_output.glob("*.tgz"))
    if len(npm_tarballs) != 2:
        raise RuntimeError(f"expected native + root npm tarballs, found {npm_tarballs}")
    native_tarball = next(
        path for path in npm_tarballs if native_metadata["name"] in path.name
    )
    root_tarball = next(path for path in npm_tarballs if path != native_tarball)

    packaged = [cli, wheel, native_tarball, root_tarball]
    files = {
        path.relative_to(output).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(packaged)
    }
    provenance = {
        "schema": 1,
        "source_sha": args.source_sha,
        "rust_target": args.target,
        "npm_platform": args.npm_platform,
        "runner": {
            "os": os.environ.get("RUNNER_OS", sys.platform),
            "arch": os.environ.get(
                "RUNNER_ARCH", os.uname().machine if os.name != "nt" else "x64"
            ),
            "image": os.environ.get("ImageOS", "local"),
        },
        "files": files,
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(json.dumps(provenance, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
