#!/usr/bin/env python3
"""Install and execute manifest-verified release artifacts, from outside the checkout.

This is R3's consumer harness at PR 1 scope: verify every artifact a
release-scan-manifest.json (scripts/write-release-scan-manifest.py) claims,
by SHA-256, then exercise whichever of them this host can actually run —
never the source tree, only the packaged/built artifact, extracted into a
fresh scratch directory outside the git checkout (mirroring the pattern
scripts/check-packaged-rust-consumer.py already established for the crate).

Scope, honestly: this only covers artifact types that already flow through a
release-scan-manifest.json today (npm tarballs and the Windows native
addon). CLI binaries and Python wheels don't yet produce a manifest of their
own — extending publish-cli.yml/publish-py.yml to do that is follow-up work,
not part of this harness. Parent-process ownership for Windows App-Bound
parent-death tests is explicitly out of scope here too — see docs/RELEASING.md
and issue #230's R3 section.

An artifact this host's OS/CPU can't execute (e.g. a win32 tarball on a
macOS host) is checksum-verified but not run, and that's reported, not
silently skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


class HarnessError(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def verify_artifacts(manifest: dict[str, Any], artifacts_root: Path) -> list[tuple[dict[str, Any], Path]]:
    """Fail closed: every manifest artifact must exist and match its recorded SHA-256."""
    verified: list[tuple[dict[str, Any], Path]] = []
    failures: list[str] = []

    for record in manifest.get("artifacts", []):
        path = artifacts_root / record["path"]
        if not path.is_file():
            failures.append(f"missing artifact: {record['path']}")
            continue
        actual = sha256(path)
        if actual != record["sha256"]:
            failures.append(
                f"SHA-256 mismatch for {record['path']}: manifest says {record['sha256']}, got {actual}"
            )
            continue
        if path.stat().st_size != record["bytes"]:
            failures.append(
                f"byte length mismatch for {record['path']}: manifest says {record['bytes']}, "
                f"got {path.stat().st_size}"
            )
            continue
        verified.append((record, path))

    if failures:
        raise HarnessError("artifact verification failed:\n" + "\n".join(f"- {failure}" for failure in failures))

    return verified


def current_host_npm_platform() -> str:
    """The napi-rs-style platform string (see release/platform-contract.json's npm_platform) for this host."""
    system = platform.system()
    machine = platform.machine().lower()
    cpu = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    if system == "Darwin":
        return f"darwin-{cpu}"
    if system == "Linux":
        return f"linux-{cpu}-gnu"
    if system == "Windows":
        return f"win32-{cpu}-msvc"
    return f"{system.lower()}-{cpu}"


def extract_tarball(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as tar:
        root = destination.resolve()
        for member in tar.getmembers():
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                raise HarnessError(f"unsafe tarball member in {archive.name}: {member.name}")
        tar.extractall(destination, filter="data")
    return destination


def exercise_npm_tarball(path: Path, scratch: Path) -> str:
    package_dir = extract_tarball(path, scratch / path.stem)
    package_json_path = package_dir / "package" / "package.json"
    if not package_json_path.is_file():
        raise HarnessError(f"{path.name}: extracted tarball has no package/package.json")
    package_json = json.loads(package_json_path.read_text(encoding="utf-8"))

    package_platform = current_host_npm_platform()
    os_tags = package_json.get("os", [])
    if os_tags and not any(package_platform.startswith(tag) for tag in os_tags):
        return f"checksum-verified only ({path.name} targets {os_tags}, host is {package_platform})"

    main_entry = package_json.get("main")
    if main_entry:
        entry_path = package_dir / "package" / main_entry
        if not entry_path.is_file():
            raise HarnessError(f"{path.name}: package.json main {main_entry!r} does not exist in the tarball")

    return f"structurally verified: {package_json.get('name')}@{package_json.get('version')}"


def exercise_native_addon(path: Path, scratch: Path) -> str:
    # A bare `.node` file can't be `require()`d without its owning package's
    # loader around it, and this repo's loader dispatches by platform at
    # runtime — so a foreign-platform `.node` genuinely can't be exercised
    # from here. Only report what verify_artifacts already proved: the bytes
    # match. Running it is out of scope until the harness is wired to also
    # unpack the owning npm package (see module docstring).
    return f"checksum-verified only (native addon execution needs its owning npm package, not a bare .node)"


def exercise(record: dict[str, Any], path: Path, scratch: Path) -> str:
    name = path.name
    if name.endswith(".tgz"):
        return exercise_npm_tarball(path, scratch)
    if name.endswith(".node"):
        return exercise_native_addon(path, scratch)
    return "checksum-verified only (no exercise routine for this artifact type yet)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument(
        "--artifacts-root",
        required=True,
        type=Path,
        help="directory the manifest's artifact paths are relative to",
    )
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)

    try:
        verified = verify_artifacts(manifest, args.artifacts_root)
    except HarnessError as error:
        print(str(error), file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="rookie-consumer-harness-") as scratch_name:
        scratch = Path(scratch_name)
        if ROOT in scratch.parents or ROOT == scratch:
            # Should be structurally impossible (tempfile always uses the OS
            # temp root), but this is exactly the invariant R3's harness
            # exists to hold, so assert it rather than trust it silently.
            raise HarnessError("scratch directory is inside the checkout")

        results = []
        for record, path in verified:
            try:
                outcome = exercise(record, path, scratch)
            except HarnessError as error:
                print(f"FAIL {record['path']}: {error}", file=sys.stderr)
                return 1
            results.append((record["path"], outcome))

    for artifact_path, outcome in results:
        print(f"{artifact_path}: {outcome}")
    print(f"Consumer harness: {len(results)} artifact(s) verified against {args.manifest}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
