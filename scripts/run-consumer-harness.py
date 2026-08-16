#!/usr/bin/env python3
"""Install and execute manifest-verified release artifacts, from outside the checkout.

This is R3's consumer harness at PR 1 scope: verify every artifact a
release-scan-manifest.json (scripts/write-release-scan-manifest.py) claims,
by SHA-256, then exercise whichever of them this host can actually run —
never the source tree, only the packaged/built artifact, extracted into a
fresh scratch directory outside the git checkout (mirroring the pattern
scripts/check-packaged-rust-consumer.py already established for the crate).

Scope, honestly: npm tarballs are exercised structurally; CLI binaries and
Python wheels are actually executed (`--version` for the CLI, an isolated
`pip install` + `import` + `version()` for wheels) when the artifact's
declared platform matches the host running this harness -- otherwise they
fall back to checksum-verified-only, which is reported, not silently
skipped. A cross-platform npm tarball gets that same fallback outcome when
its declared platform doesn't match the host. A native `.node` addon always
gets it too, unconditionally: it can't be `require()`d without its owning
npm package (see `exercise_native_addon`). A Python sdist has no compiled
platform to match against and always falls through the same way; building
one from source isn't a meaningful smoke check for this harness.
`publish-npm.yml`, `publish-cli.yml`, and `publish-py.yml` all now write a
manifest and call this harness before their respective registry writes.

This still isn't full per-helper-role live extraction (no real Keychain/
DPAPI/keyring/App-Bound credential read happens here — the Windows App-Bound
v20 canary in e2e.yml is the closest thing to that, and it exercises a
separate dev build, not the exact release artifact). "Supervised cell" /
parent-death-canary / arm-containment-before-spawn semantics from the
original PR6 spec are not implemented here or anywhere else in this
codebase: no helper role is spawned as a separately supervised child
process today (each runs in-process), so there is no containment surface to
arm — see docs/RELEASING.md's "Packaging-proof: what this harness actually
proves" section for the honest accounting of what is and isn't covered, and
issue #230's R3 section for prior context.

An artifact this host's OS/CPU can't execute (e.g. a win32 tarball on a
macOS host) is checksum-verified but not run, and that's reported, not
silently skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
sys.path.insert(0, str(Path(__file__).resolve().parent))
import jcs  # noqa: E402
import platform_contract  # noqa: E402


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


def verify_artifacts(
    manifest: dict[str, Any], artifacts_root: Path, contract: dict[str, Any] | None = None
) -> list[tuple[dict[str, Any], Path]]:
    """Fail closed: every manifest artifact must exist and match its recorded
    SHA-256, and (when the manifest and `contract` both carry the
    information -- see `write-release-scan-manifest.py` schema_version 3)
    its recorded `helper_roles` must still match the *current*
    platform-contract.json, not just the one it was written against. A
    manifest is written once; re-deriving and comparing here catches the
    contract changing helper roles for a cell between write time and this
    harness run, not just a corrupted or substituted artifact.
    """
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
        if contract is not None and "helper_roles" in record:
            try:
                cell = platform_contract.match_cell_for_artifact(contract, path.name)
            except platform_contract.ArtifactMatchError as error:
                failures.append(f"{record['path']}: {error}")
                continue
            expected = sorted(cell.get("helper_roles", [])) if cell is not None else None
            if expected != sorted(record["helper_roles"]):
                failures.append(
                    f"{record['path']}: manifest helper_roles {record['helper_roles']} no longer matches "
                    f"the current platform contract's {expected} for this artifact"
                )
                continue
        verified.append((record, path))

    if failures:
        raise HarnessError("artifact verification failed:\n" + "\n".join(f"- {failure}" for failure in failures))

    return verified


def current_host_npm_os_cpu() -> tuple[str, str]:
    """The (os, cpu) pair npm package.json's `os`/`cpu` restriction fields use for this host."""
    system = platform.system()
    machine = platform.machine().lower()
    cpu = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine, machine)
    os_name = {"Darwin": "darwin", "Linux": "linux", "Windows": "win32"}.get(system, system.lower())
    return os_name, cpu


def current_host_npm_platform() -> str:
    """The napi-rs-style platform string (see release/platform-contract.json's npm_platform) for this host."""
    system = platform.system()
    os_name, cpu = current_host_npm_os_cpu()
    if system == "Darwin":
        return f"darwin-{cpu}"
    if system == "Linux":
        return f"linux-{cpu}-gnu"
    if system == "Windows":
        return f"win32-{cpu}-msvc"
    return f"{system.lower()}-{cpu}"


def cli_binary_target(name: str) -> str | None:
    """The target triple embedded in a CLI artifact filename, or `None` if
    `name` isn't shaped like one (see `publish-cli.yml`'s
    `rookie-cookies-cli-<target>[.exe]` naming)."""
    if not name.startswith("rookie-cookies-cli-"):
        return None
    target = name.removeprefix("rookie-cookies-cli-")
    return target.removesuffix(".exe")


def wheel_platform_os_cpu(name: str) -> tuple[str, str] | None:
    """The (os, cpu) pair a `.whl` filename's platform tag targets, in the
    same vocabulary `current_host_npm_os_cpu()` uses, or `None` for a
    platform-independent tag (a pure-Python wheel's `any` tag) this harness
    can't usefully compare against a host. A sdist never reaches this
    function at all -- it isn't a `.whl` file.

    Deliberately coarser than `platform_contract._wheel_cell_os_cpu`: this
    only needs to answer "can the current host run it", not identify the
    exact contract cell, so it doesn't need that function's full arch
    vocabulary (i686/armv7l/s390x/ppc64le).
    """
    # PEP 425: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    platform_tag = name.removesuffix(".whl").rsplit("-", 1)[-1]
    if "macosx" in platform_tag:
        os_name = "darwin"
    elif "manylinux" in platform_tag or "linux" in platform_tag:
        os_name = "linux"
    elif platform_tag.startswith("win"):
        os_name = "win32"
    else:
        return None
    if "arm64" in platform_tag or "aarch64" in platform_tag:
        cpu = "arm64"
    elif "x86_64" in platform_tag or "amd64" in platform_tag:
        cpu = "x64"
    else:
        return None
    return os_name, cpu


def exercise_cli_binary(path: Path, scratch: Path, contract: dict[str, Any]) -> str:
    target = cli_binary_target(path.name)
    if target is None:
        raise HarnessError(f"{path.name}: does not match the rookie-cookies-cli-<target> naming")
    # Reuses the same contract lookup verify_artifacts() already trusts for
    # helper_roles, instead of a second hardcoded target->(os, cpu) table
    # that could silently drift from it -- see platform_contract.py's own
    # module docstring on why this project stopped doing that.
    cell = platform_contract.match_cell_for_artifact(contract, path.name)
    target_os_cpu = (cell["os"], cell["cpu"]) if cell is not None else None
    host_os, host_cpu = current_host_npm_os_cpu()
    if target_os_cpu != (host_os, host_cpu):
        return (
            f"checksum-verified only ({path.name} targets {target}, "
            f"host is {host_os}/{host_cpu})"
        )

    runnable = scratch / path.name
    shutil.copy2(path, runnable)
    runnable.chmod(runnable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    try:
        result = subprocess.run(
            [str(runnable), "--version"],
            cwd=scratch,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError(f"{path.name}: --version did not complete within {error.timeout}s") from error
    except OSError as error:
        raise HarnessError(f"{path.name}: could not execute --version: {error}") from error
    if result.returncode != 0:
        raise HarnessError(
            f"{path.name}: --version exited {result.returncode}: {result.stderr.strip()}"
        )
    version = result.stdout.strip()
    if not version:
        raise HarnessError(f"{path.name}: --version produced no output")
    return f"executed outside the checkout: --version reported {version!r}"


def exercise_python_wheel(path: Path, scratch: Path) -> str:
    target_os_cpu = wheel_platform_os_cpu(path.name)
    host_os, host_cpu = current_host_npm_os_cpu()
    if target_os_cpu is None or target_os_cpu != (host_os, host_cpu):
        return (
            f"checksum-verified only ({path.name} targets "
            f"{target_os_cpu or 'an unrecognized platform tag'}, host is {host_os}/{host_cpu})"
        )

    venv_dir = scratch / f"{path.stem}-venv"
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        venv_python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--no-index", "--no-deps", str(path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        result = subprocess.run(
            [str(venv_python), "-c", "import rookie_cookies; print(rookie_cookies.version())"],
            cwd=scratch,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError(
            f"{path.name}: install-and-import did not complete within {error.timeout}s"
        ) from error
    except subprocess.CalledProcessError as error:
        raise HarnessError(
            f"{path.name}: install-and-import failed outside the checkout: {error.stderr.strip()}"
        ) from error
    except OSError as error:
        raise HarnessError(f"{path.name}: could not create an isolated venv: {error}") from error
    version = result.stdout.strip()
    if not version:
        raise HarnessError(f"{path.name}: import succeeded but version() produced no output")
    return f"installed into an isolated venv outside the checkout: version() reported {version!r}"


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

    host_os, host_cpu = current_host_npm_os_cpu()
    os_tags = package_json.get("os", [])
    cpu_tags = package_json.get("cpu", [])
    os_matches = not os_tags or host_os in os_tags
    cpu_matches = not cpu_tags or host_cpu in cpu_tags
    if not (os_matches and cpu_matches):
        return (
            f"checksum-verified only ({path.name} targets os={os_tags or 'any'}/cpu={cpu_tags or 'any'}, "
            f"host is {host_os}/{host_cpu})"
        )

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


def exercise(record: dict[str, Any], path: Path, scratch: Path, contract: dict[str, Any]) -> str:
    name = path.name
    if name.endswith(".tgz"):
        return exercise_npm_tarball(path, scratch)
    if name.endswith(".node"):
        return exercise_native_addon(path, scratch)
    if name.endswith(".whl"):
        return exercise_python_wheel(path, scratch)
    if cli_binary_target(name) is not None:
        return exercise_cli_binary(path, scratch, contract)
    return "checksum-verified only (no exercise routine for this artifact type yet)"


# `artifact_id`s this harness gives real (structural-or-better, not just
# checksum-verified-only) coverage to, via `exercise()`'s dispatch above.
# `npm-native`'s raw `.node` addon alone stays checksum-verified-only (see
# `exercise_native_addon`), but every `npm-native` cell always ships paired
# with the native tarball that structurally exercises the same install, so
# the cell as a whole is still covered.
_ARTIFACT_IDS_WITH_EXERCISE_COVERAGE = {"npm-root", "npm-native", "cli", "wheel"}

# `execute: "native"` artifact_ids that deliberately have no exercise()
# coverage and never will, so they don't belong in the set above but also
# aren't a gap `check_native_execution_coverage` should flag:
#   - "crate": published straight from source by `publish-crate.yml`, which
#     never writes a release-scan-manifest.json or calls this harness at
#     all -- there is no artifact here to have coverage for.
#   - "sdist": always falls through to checksum-verified-only, deliberately
#     -- building a wheel from source isn't a meaningful smoke check for
#     this harness (see the module docstring).
_ARTIFACT_IDS_DELIBERATELY_UNCOVERED = {"crate", "sdist"}


def check_native_execution_coverage(contract: dict[str, Any]) -> list[str]:
    """Every `execute: "native"` cell must have real exercise() coverage for
    *some* artifact of its type (or be one of the deliberate, documented
    exceptions above), or that classification is asserting something this
    harness can't back up.
    """
    failures = []
    for cell in platform_contract.cells(contract):
        if cell.get("execute") != "native":
            continue
        artifact_id = cell.get("artifact_id")
        if artifact_id in _ARTIFACT_IDS_DELIBERATELY_UNCOVERED:
            continue
        if artifact_id not in _ARTIFACT_IDS_WITH_EXERCISE_COVERAGE:
            failures.append(
                f"cell {cell!r}: execute=native but artifact_id {artifact_id!r} has no "
                "exercise() routine in run-consumer-harness.py"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-native-coverage",
        action="store_true",
        help=(
            "check that every platform-contract.json cell marked execute=native has real "
            "exercise() coverage, and exit -- ignores --manifest/--artifacts-root"
        ),
    )
    parser.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--artifacts-root",
        type=Path,
        help="directory the manifest's artifact paths are relative to",
    )
    parser.add_argument(
        "--platform-contract",
        type=Path,
        default=platform_contract.DEFAULT_CONTRACT_PATH,
        help="path to platform-contract.json, for re-checking each artifact's manifest helper_roles",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "write a structured JSON evidence record to this path, bound to the "
            "manifest's release.manifest_digest (schema_version 4+; see "
            "write-release-scan-manifest.py) -- see release-hardening program R4. "
            "Does not change stdout/exit-code behavior."
        ),
    )
    args = parser.parse_args()

    contract = platform_contract.load_contract(args.platform_contract)

    if args.check_native_coverage:
        failures = check_native_execution_coverage(contract)
        if failures:
            print("Native execution coverage check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        print("Every execute=native cell has exercise() coverage.")
        return 0

    if args.manifest is None or args.artifacts_root is None:
        parser.error("--manifest and --artifacts-root are required unless --check-native-coverage is given")

    manifest = load_manifest(args.manifest)

    release = manifest.get("release")
    manifest_digest = release.get("manifest_digest") if isinstance(release, dict) else None
    if args.output is not None and not (
        isinstance(manifest_digest, str) and _MANIFEST_DIGEST_PATTERN.fullmatch(manifest_digest)
    ):
        print(
            f"{args.manifest}: --output was given but release.manifest_digest is missing or "
            f"not a valid SHA-256 hex digest (got {manifest_digest!r}; schema_version 4+ "
            "required; see write-release-scan-manifest.py)",
            file=sys.stderr,
        )
        return 1

    if args.output is not None:
        # The digest is otherwise write-only: copied verbatim from the
        # manifest into the evidence record without ever being checked
        # against the document it claims to bind. Recompute it the same way
        # write-release-scan-manifest.py does (see that script for why the
        # comparison excludes the manifest_digest field itself) so evidence
        # can't attest to bytes that were never actually verified -- a
        # manifest whose release/artifacts drifted from each other (a
        # partial edit, a bad merge) would otherwise carry a stale digest
        # straight through into "evidence."
        expected_digest = jcs.digest(
            {
                "release": {key: value for key, value in release.items() if key != "manifest_digest"},
                "artifacts": manifest.get("artifacts", []),
            }
        )
        if expected_digest != manifest_digest:
            print(
                f"{args.manifest}: release.manifest_digest {manifest_digest!r} does not match "
                f"the manifest's actual content (recomputed {expected_digest!r})",
                file=sys.stderr,
            )
            return 1

    try:
        verified = verify_artifacts(manifest, args.artifacts_root, contract)
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
                outcome = exercise(record, path, scratch, contract)
            except HarnessError as error:
                print(f"FAIL {record['path']}: {error}", file=sys.stderr)
                return 1
            results.append((record["path"], outcome))

    for artifact_path, outcome in results:
        print(f"{artifact_path}: {outcome}")
    print(f"Consumer harness: {len(results)} artifact(s) verified against {args.manifest}.")

    if args.output is not None:
        host_os, host_cpu = current_host_npm_os_cpu()
        evidence = {
            "schema_version": 1,
            "manifest_digest": manifest_digest,
            "host": {"os": host_os, "cpu": host_cpu},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results": [
                {"path": artifact_path, "outcome": outcome}
                for artifact_path, outcome in results
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
