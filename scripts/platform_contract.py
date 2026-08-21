"""Shared loader/validator for release/platform-contract.json.

`release/platform-contract.json` is the single source of truth for every
artifact/platform "cell" this project builds, advertises, publishes, and
(where applicable) executes on real hardware before publishing. Before this
existed, the same information was spelled out independently in at least five
places (two workflow matrices, a third workflow's target list, and two
separate `NATIVE_PACKAGES` tuples) with nothing to catch them drifting apart.
Every script that used to hardcode its own copy of the npm native-package
list now calls `npm_native_packages()` here instead.

This is a plain module (not a `scripts/*.py` CLI-only script) so both
`scripts/check-release.py` and `scripts/bump-version.py` can import it
directly; run it as `python3 scripts/platform_contract.py --validate` for
the standalone CI check.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT_PATH = ROOT / "release" / "platform-contract.json"

VALID_EXECUTE_STATES = {"native", "qemu", "untested"}
VALID_REGISTRIES = {"crates.io", "npm", "pypi", "github-release"}
VALID_HELPER_ROLES = {"keychain", "dpapi", "appbound", "keyring"}

# Helper roles that need real access to an OS credential store to mean
# anything — a cell claiming one of these while `execute` isn't "native"
# is exactly the risk this contract exists to make visible, not to forbid
# outright (an accepted_risk entry, checked below, is how a maintainer signs
# off on it deliberately instead of it happening silently).
OS_CREDENTIAL_STORE_ROLES = {"keychain", "dpapi", "appbound"}


class ContractError(Exception):
    pass


def load_contract(path: Path = DEFAULT_CONTRACT_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def cells(contract: dict[str, Any], *, artifact_id: str | None = None) -> list[dict[str, Any]]:
    result = contract.get("cells", [])
    if artifact_id is not None:
        result = [cell for cell in result if cell.get("artifact_id") == artifact_id]
    return result


def cli_matrix(contract: dict[str, Any]) -> dict[str, Any]:
    """`{"include": [...]}` for publish-cli.yml's build matrix."""
    include = []
    for cell in sorted(cells(contract, artifact_id="cli"), key=lambda c: c["target_triple"]):
        if not cell["build"]:
            continue
        entry = {"platform": cell["runner"], "target": cell["target_triple"]}
        if cell["features"]:
            entry["args"] = f"--features {','.join(cell['features'])}"
        include.append(entry)
    return {"include": include}


def npm_native_matrix(contract: dict[str, Any]) -> dict[str, Any]:
    """`{"settings": [...]}` for publish-npm.yml's `build` job matrix."""
    settings = []
    for cell in sorted(cells(contract, artifact_id="npm-native"), key=lambda c: c["target_triple"]):
        if not cell["build"]:
            continue
        entry = {
            "host": cell["runner"],
            "target": cell["target_triple"],
            "build": f"npm run build -- --target {cell['target_triple']} --cargo-flags=--locked",
        }
        if "docker_image" in cell:
            entry["docker"] = cell["docker_image"]
        settings.append(entry)
    return {"settings": settings}


def wheel_targets(contract: dict[str, Any], os_name: str) -> list[str]:
    """Sorted maturin target strings (== each wheel cell's `cpu`) for one OS.

    Matrix order doesn't affect what gets published for a `fail-fast: false`
    matrix — every combination still runs — so alphabetical is fine here.
    """
    return sorted(
        cell["cpu"]
        for cell in cells(contract, artifact_id="wheel")
        if cell["os"] == os_name and cell["build"]
    )


def wheel_linux_matrix(contract: dict[str, Any]) -> dict[str, Any]:
    """`{"include": [...]}` so linux aarch64 can run on ubuntu-24.04-arm."""
    include = []
    for cpu in wheel_targets(contract, "linux"):
        matches = [
            cell
            for cell in cells(contract, artifact_id="wheel")
            if cell["os"] == "linux" and cell["cpu"] == cpu and cell["build"]
        ]
        runner = matches[0].get("runner") if matches else None
        include.append({"target": cpu, "runner": runner or "ubuntu-latest"})
    return {"include": include}


def npm_native_packages(contract: dict[str, Any]) -> tuple[str, ...]:
    """Native npm package names, in the same order the old hardcoded tuple used.

    Sorting `npm_platform` alphabetically happens to reproduce a stable
    order (darwin-arm64, darwin-x64, linux-arm64-gnu, linux-x64-gnu,
    win32-x64-msvc) without needing a separate explicit ordering field.
    """
    platforms = sorted(cell["npm_platform"] for cell in cells(contract, artifact_id="npm-native"))
    return tuple(f"rookie-cookies-{platform}" for platform in platforms)


def npm_publish_packages(contract: dict[str, Any]) -> tuple[str, ...]:
    """npm packages to publish, with native packages before the root loader.

    The order is significant: the root package declares every native package
    as an optional dependency, so publishing it last avoids exposing a root
    version whose platform package is not available yet.
    """
    native = sorted(
        f"rookie-cookies-{cell['npm_platform']}"
        for cell in cells(contract, artifact_id="npm-native")
        if cell.get("registry") == "npm" and cell.get("publish") is True
    )
    if len(native) != len(set(native)):
        raise ContractError(f"published npm package names are not unique: {native}")
    roots = [
        cell
        for cell in cells(contract, artifact_id="npm-root")
        if cell.get("registry") == "npm" and cell.get("publish") is True
    ]
    if len(roots) != 1:
        raise ContractError(
            f"expected exactly one published npm-root cell, found {len(roots)}"
        )
    return (*native, "rookie-cookies")


def npm_publish_tarballs(contract: dict[str, Any], version: str) -> tuple[str, ...]:
    """Expected immutable npm tarball basenames in publish order."""
    return tuple(f"{package}-{version}.tgz" for package in npm_publish_packages(contract))


def validate_npm_repository(
    contract: dict[str, Any], node_root: Path = ROOT / "bindings" / "node"
) -> list[str]:
    """Cross-check the npm contract against checked-in package metadata.

    This deliberately validates exact sets. A newly checked-in native package,
    optional dependency, or published contract cell must be represented by all
    three surfaces before a release can proceed.
    """
    failures: list[str] = []
    try:
        published = npm_publish_packages(contract)
    except ContractError as error:
        return [str(error)]
    expected_native_names = set(published[:-1])
    expected_platforms = {
        package.removeprefix("rookie-cookies-") for package in expected_native_names
    }

    npm_root = node_root / "npm"
    try:
        actual_platforms = {
            path.name
            for path in npm_root.iterdir()
            if path.is_dir() and (path / "package.json").is_file()
        }
    except OSError as error:
        return [f"cannot read native npm package directory {npm_root}: {error}"]
    if actual_platforms != expected_platforms:
        failures.append(
            "checked-in native npm directories do not match published contract cells: "
            f"expected {sorted(expected_platforms)}, found {sorted(actual_platforms)}"
        )

    try:
        root_metadata = json.loads((node_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"cannot read npm root package metadata: {error}"]
    optional_dependencies = root_metadata.get("optionalDependencies")
    actual_optional_names = (
        set(optional_dependencies) if isinstance(optional_dependencies, dict) else set()
    )
    if actual_optional_names != expected_native_names:
        failures.append(
            "root optionalDependencies do not match published native contract cells: "
            f"expected {sorted(expected_native_names)}, found {sorted(actual_optional_names)}"
        )
    if root_metadata.get("name") != "rookie-cookies":
        failures.append(
            f"root npm package name must be 'rookie-cookies', found {root_metadata.get('name')!r}"
        )
    if isinstance(optional_dependencies, dict):
        for package_name in sorted(expected_native_names & actual_optional_names):
            if optional_dependencies[package_name] != root_metadata.get("version"):
                failures.append(
                    f"root optional dependency {package_name} must use root version "
                    f"{root_metadata.get('version')!r}, found {optional_dependencies[package_name]!r}"
                )

    cells_by_platform = {
        cell["npm_platform"]: cell
        for cell in cells(contract, artifact_id="npm-native")
        if cell.get("registry") == "npm" and cell.get("publish") is True
    }
    # npm's `libc` selector is meaningful on Linux. The contract still records
    # Windows' ABI as `msvc`, but npm package metadata correctly omits it.
    npm_libc = {None: None, "gnu": "glibc", "musl": "musl", "msvc": None}
    for platform_name in sorted(expected_platforms & actual_platforms):
        metadata_path = npm_root / platform_name / "package.json"
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            failures.append(f"cannot read {metadata_path}: {error}")
            continue
        cell = cells_by_platform[platform_name]
        expected = {
            "name": f"rookie-cookies-{platform_name}",
            "os": [cell["os"]],
            "cpu": [cell["cpu"]],
            "main": f"rookie_cookies.{platform_name}.node",
        }
        expected_libc = npm_libc.get(cell.get("libc"), cell.get("libc"))
        if expected_libc is not None:
            expected["libc"] = [expected_libc]
        for key, expected_value in expected.items():
            if metadata.get(key) != expected_value:
                failures.append(
                    f"{metadata_path}: {key} must be {expected_value!r}, "
                    f"found {metadata.get(key)!r}"
                )
        if expected_libc is None and "libc" in metadata:
            failures.append(
                f"{metadata_path}: libc must be absent for contract libc=null"
            )
        if metadata.get("version") != root_metadata.get("version"):
            failures.append(
                f"{metadata_path}: version {metadata.get('version')!r} does not match "
                f"root version {root_metadata.get('version')!r}"
            )

    return failures


class ArtifactMatchError(Exception):
    """Raised when a release artifact's filename can't be matched to exactly
    one contract cell -- see `match_cell_for_artifact`."""


_CLI_BINARY_PATTERN = re.compile(r"^rookie-cookies-cli-(?P<target>.+?)(?:\.exe)?$")
_NPM_ADDON_PATTERN = re.compile(r"^rookie_cookies\.(?P<npm_platform>[a-z0-9]+(?:-[a-z0-9]+)+)\.node$")

# PEP 425/600 wheel platform-tag arch tokens this project's cells can appear
# under, keyed by the contract's own `cpu` vocabulary. macOS and manylinux
# spell some architectures differently from both each other and from Rust's
# target-triple arch component (e.g. a manylinux tag says "aarch64" where a
# macOS tag says "arm64"; "x86" is "i686" on both), so this isn't a single
# substring check.
_WHEEL_CPU_TAGS = {
    "darwin": {
        "x86_64": {"x86_64"},
        "aarch64": {"arm64"},
    },
    "linux": {
        "x86_64": {"x86_64"},
        "x86": {"i686"},
        "aarch64": {"aarch64"},
        "armv7": {"armv7l"},
        "s390x": {"s390x"},
        "ppc64le": {"ppc64le"},
    },
    "win32": {
        "x64": {"amd64"},
    },
}


def _wheel_cell_os_cpu(platform_tag: str) -> tuple[str, str] | None:
    # A compressed manylinux tag looks like "manylinux_2_17_x86_64.manylinux2014_x86_64";
    # every dot-separated alternative names the same architecture, so only the first is needed.
    tag = platform_tag.split(".")[0]
    if tag.startswith("macosx"):
        os_name = "darwin"
    elif tag.startswith("manylinux") or tag.startswith("linux"):
        os_name = "linux"
    elif tag.startswith("win"):
        os_name = "win32"
    else:
        return None
    for cpu, tokens in _WHEEL_CPU_TAGS[os_name].items():
        if any(tag.endswith(f"_{token}") for token in tokens):
            return os_name, cpu
    return None


def match_cell_for_artifact(contract: dict[str, Any], filename: str) -> dict[str, Any] | None:
    """The single contract cell `filename` (a release artifact's basename, as
    written into a release-scan-manifest.json record) was built for, or
    `None` if `filename` isn't shaped like any artifact this project
    publishes. Filename shapes are taken from the exact `write-release-scan-manifest.py`
    invocations in `publish-cli.yml`/`publish-npm.yml`/`publish-py.yml`, not
    guessed.
    """
    addon_match = _NPM_ADDON_PATTERN.match(filename)
    if addon_match:
        npm_platform = addon_match["npm_platform"]
        matches = [
            cell for cell in cells(contract, artifact_id="npm-native") if cell.get("npm_platform") == npm_platform
        ]
        return matches[0] if matches else None

    if filename.endswith(".tgz"):
        for cell in cells(contract, artifact_id="npm-native"):
            npm_platform = cell.get("npm_platform")
            if npm_platform and filename.startswith(f"rookie-cookies-{npm_platform}-"):
                return cell
        matches = cells(contract, artifact_id="npm-root")
        return matches[0] if matches else None

    cli_match = _CLI_BINARY_PATTERN.match(filename)
    if cli_match:
        target = cli_match["target"]
        matches = [cell for cell in cells(contract, artifact_id="cli") if cell.get("target_triple") == target]
        return matches[0] if matches else None

    if filename.endswith(".whl"):
        platform_tag = filename.removesuffix(".whl").rsplit("-", 1)[-1]
        os_cpu = _wheel_cell_os_cpu(platform_tag)
        if os_cpu is None:
            raise ArtifactMatchError(
                f"{filename}: wheel platform tag {platform_tag!r} does not match any known "
                "architecture token -- see platform_contract.py's _WHEEL_CPU_TAGS"
            )
        os_name, cpu = os_cpu
        matches = [
            cell for cell in cells(contract, artifact_id="wheel") if cell.get("os") == os_name and cell.get("cpu") == cpu
        ]
        if not matches:
            raise ArtifactMatchError(f"{filename}: no wheel cell declared for os={os_name!r} cpu={cpu!r}")
        return matches[0]

    if filename.endswith(".tar.gz"):
        matches = cells(contract, artifact_id="sdist")
        return matches[0] if matches else None

    if filename.endswith(".crate"):
        matches = cells(contract, artifact_id="crate")
        return matches[0] if matches else None

    return None


# Fields that are optional/artifact-specific in the schema (unlike os/cpu/
# libc, which every cell has, sometimes null) but that emit_matrix()'s
# per-artifact-type functions access unconditionally via plain dict
# indexing. A cell missing one of these passes JSON structure but would
# otherwise only surface as a raw KeyError from whichever downstream script
# happens to touch it first — validate() catches it here instead, with a
# message that names the cell and the missing field.
REQUIRED_KEYS_BY_ARTIFACT = {
    "cli": ("target_triple", "runner"),
    "npm-native": ("target_triple", "runner", "npm_platform"),
    "wheel": ("cpu",),
}


def _validate_accepted_risk(entry: Any, *, label: str, today: date) -> list[str]:
    failures: list[str] = []
    if not isinstance(entry, dict):
        return [f"{label}: accepted_risk must be an object, got {entry!r}"]

    owner = entry.get("owner")
    if not isinstance(owner, str) or not owner.strip():
        failures.append(f"{label}: accepted_risk.owner is required")

    rationale = entry.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        failures.append(f"{label}: accepted_risk.rationale is required")

    expires = entry.get("expires")
    if not isinstance(expires, str):
        failures.append(f"{label}: accepted_risk.expires is required (ISO-8601 date)")
    else:
        try:
            expiry_date = date.fromisoformat(expires)
        except ValueError:
            failures.append(f"{label}: accepted_risk.expires {expires!r} is not a valid ISO-8601 date")
        else:
            if expiry_date < today:
                failures.append(f"{label}: accepted_risk expired on {expiry_date.isoformat()}")

    return failures


def validate(contract: dict[str, Any], *, today: date | None = None) -> list[str]:
    today = today or date.today()
    failures: list[str] = []
    seen_keys: set[tuple[Any, ...]] = set()

    for index, cell in enumerate(cells(contract)):
        artifact_id = cell.get("artifact_id", f"<cell {index}>")
        label = f"cell {index} ({artifact_id})"

        key = (artifact_id, cell.get("registry"), cell.get("os"), cell.get("cpu"), cell.get("libc"))
        if key in seen_keys:
            failures.append(f"{label}: duplicate cell for {key}")
        seen_keys.add(key)

        for required_key in REQUIRED_KEYS_BY_ARTIFACT.get(artifact_id, ()):
            if cell.get(required_key) is None:
                failures.append(f"{label}: missing required field {required_key!r} for artifact_id {artifact_id!r}")

        registry = cell.get("registry")
        if registry not in VALID_REGISTRIES:
            failures.append(f"{label}: registry {registry!r} is not one of {sorted(VALID_REGISTRIES)}")

        execute = cell.get("execute")
        if execute not in VALID_EXECUTE_STATES:
            failures.append(f"{label}: execute {execute!r} is not one of {sorted(VALID_EXECUTE_STATES)}")

        helper_roles = cell.get("helper_roles", [])
        unknown_roles = set(helper_roles) - VALID_HELPER_ROLES
        if unknown_roles:
            failures.append(f"{label}: unknown helper_roles {sorted(unknown_roles)}")

        build, advertise, publish = cell.get("build"), cell.get("advertise"), cell.get("publish")
        if publish and not advertise:
            failures.append(f"{label}: publish=true requires advertise=true")
        if advertise and not build:
            failures.append(f"{label}: advertise=true requires build=true")

        accepted_risk = cell.get("accepted_risk")
        if advertise and execute != "native":
            if accepted_risk is None:
                failures.append(
                    f"{label}: advertise=true with execute={execute!r} (not native) requires accepted_risk"
                )
            else:
                failures.extend(_validate_accepted_risk(accepted_risk, label=label, today=today))
        elif accepted_risk is not None:
            failures.append(f"{label}: accepted_risk is set but execute=native does not need one")

    return failures


def contract_digest(path: Path = DEFAULT_CONTRACT_PATH) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _cell_identity(cell: dict[str, Any]) -> tuple[Any, ...]:
    # The same compound key validate() uses to detect duplicate cells
    # (artifact_id alone is not unique -- the real contract has several `wheel`
    # cells, several `npm-native` cells, and several `cli` cells, one per platform/libc
    # combination). Keying only on artifact_id would silently collapse all
    # of a real artifact_id's cells down to whichever one happens to be
    # last in list order, hiding a changed or newly-added cell whenever a
    # sibling cell with the same artifact_id already exists.
    return (
        cell.get("artifact_id"),
        cell.get("registry"),
        cell.get("os"),
        cell.get("cpu"),
        cell.get("libc"),
    )


def diff_cells(base_contract: dict[str, Any], head_contract: dict[str, Any]) -> list[str]:
    """The sorted, de-duplicated `artifact_id`s of cells that are new in
    `head_contract` or whose content differs from `base_contract` --
    release-hardening program R4's "does this PR add or change an
    artifact/helper cell" signal, since the contract schema itself carries
    no `added_in`/`new` provenance field.

    Cells are matched between `base_contract` and `head_contract` by their
    full identity (`_cell_identity`, the same tuple `validate()` uses),
    not by `artifact_id` alone -- an `artifact_id` can have many cells (one
    per platform/libc combination). A cell whose identity is present in
    both with identical content is not reported. One present in
    `base_contract` but removed in `head_contract` is not reported either:
    this only answers "does head introduce or change a cell that needs
    fresh candidate-bundle evidence", not "what changed about the set as a
    whole". The returned list reports each affected `artifact_id` once,
    even if multiple of its cells changed.
    """
    base_by_identity = {_cell_identity(cell): cell for cell in cells(base_contract)}
    head_by_identity = {_cell_identity(cell): cell for cell in cells(head_contract)}
    changed_artifact_ids = {
        identity[0]
        for identity, cell in head_by_identity.items()
        if identity not in base_by_identity or base_by_identity[identity] != cell
    }
    return sorted(changed_artifact_ids)


def _repo_root_for(path: Path) -> Path:
    import subprocess

    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=path.parent,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ContractError(
            f"cannot find a git repository containing {path}: {result.stderr.strip()}"
        )
    return Path(result.stdout.strip())


def _load_contract_at_ref(ref: str, contract_path: Path) -> dict[str, Any]:
    import subprocess

    if ref.startswith("-"):
        # `git show <ref>:<path>` would otherwise treat a leading `-` as an
        # option rather than a revision. `git show -- <ref>:<path>` is not a
        # fix -- it makes git parse the whole `<ref>:<path>` as a bare
        # pathspec instead of a revision, which breaks every legitimate call.
        # Refs come from GitHub's own SHA/ref context in production, so this
        # is unreachable there, but a plain check-and-reject here is correct
        # where a `--` workaround would not have been.
        raise ContractError(f"refusing a ref that looks like an option: {ref!r}")

    resolved = contract_path.resolve()
    repo_root = _repo_root_for(resolved)
    relative = resolved.relative_to(repo_root).as_posix()
    result = subprocess.run(
        ["git", "show", f"{ref}:{relative}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ContractError(
            f"cannot read {relative} at {ref}: {result.stderr.strip() or 'git show failed'}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ContractError(f"{relative} at {ref} is not valid JSON: {error}") from error


_EMITTABLE_MATRICES = ("cli", "npm-native", "wheel-linux", "wheel-win32", "wheel-darwin")


def emit_matrix(contract: dict[str, Any], name: str) -> Any:
    if name == "cli":
        return cli_matrix(contract)
    if name == "npm-native":
        return npm_native_matrix(contract)
    if name == "wheel-linux":
        return wheel_linux_matrix(contract)
    if name.startswith("wheel-"):
        return {"target": wheel_targets(contract, name.removeprefix("wheel-"))}
    raise ContractError(f"unknown matrix name {name!r}, expected one of {_EMITTABLE_MATRICES}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT_PATH)
    parser.add_argument("--validate", action="store_true", help="validate the contract and exit")
    parser.add_argument("--digest", action="store_true", help="print the contract's SHA-256 digest and exit")
    parser.add_argument(
        "--validate-npm-repository",
        action="store_true",
        help="cross-check published npm cells against package manifests and optionalDependencies",
    )
    parser.add_argument(
        "--emit-npm-publish-order",
        action="store_true",
        help="print published npm package names, one per line, with the root package last",
    )
    parser.add_argument(
        "--emit-npm-tarballs",
        metavar="VERSION",
        help="print expected npm tarball basenames for VERSION, one per line, in publish order",
    )
    parser.add_argument(
        "--emit-matrix",
        choices=_EMITTABLE_MATRICES,
        help="print one workflow's build matrix as compact JSON (for GitHub Actions fromJSON) and exit",
    )
    parser.add_argument(
        "--diff-cells",
        nargs=2,
        metavar=("BASE_SHA", "HEAD_SHA"),
        help=(
            "print, one per line, the artifact_ids of cells added or changed in "
            "--contract between BASE_SHA and HEAD_SHA (release-hardening program "
            "R4); prints nothing and exits 0 if none changed"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.digest:
        print(contract_digest(args.contract))
        return 0

    if args.emit_npm_publish_order:
        contract = load_contract(args.contract)
        for package in npm_publish_packages(contract):
            print(package)
        return 0

    if args.emit_npm_tarballs:
        contract = load_contract(args.contract)
        for tarball in npm_publish_tarballs(contract, args.emit_npm_tarballs):
            print(tarball)
        return 0

    if args.emit_matrix:
        contract = load_contract(args.contract)
        print(json.dumps(emit_matrix(contract, args.emit_matrix), separators=(",", ":")))
        return 0

    if args.diff_cells:
        base_sha, head_sha = args.diff_cells
        try:
            base_contract = _load_contract_at_ref(base_sha, args.contract)
            head_contract = _load_contract_at_ref(head_sha, args.contract)
        except ContractError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1
        for artifact_id in diff_cells(base_contract, head_contract):
            print(artifact_id)
        return 0

    contract = load_contract(args.contract)
    failures = validate(contract)
    if args.validate_npm_repository:
        failures.extend(validate_npm_repository(contract))
    if failures:
        print("Platform contract is invalid:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Platform contract is valid: {len(cells(contract))} cells.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
