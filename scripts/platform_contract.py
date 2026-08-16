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


def npm_native_packages(contract: dict[str, Any]) -> tuple[str, ...]:
    """Native npm package names, in the same order the old hardcoded tuple used.

    Sorting `npm_platform` alphabetically happens to reproduce that exact
    order (darwin-arm64, darwin-x64, linux-x64-gnu, win32-x64-msvc) without
    needing a separate explicit ordering field.
    """
    platforms = sorted(cell["npm_platform"] for cell in cells(contract, artifact_id="npm-native"))
    return tuple(f"rookie-cookies-{platform}" for platform in platforms)


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


_EMITTABLE_MATRICES = ("cli", "npm-native", "wheel-linux", "wheel-win32", "wheel-darwin")


def emit_matrix(contract: dict[str, Any], name: str) -> Any:
    if name == "cli":
        return cli_matrix(contract)
    if name == "npm-native":
        return npm_native_matrix(contract)
    if name.startswith("wheel-"):
        return {"target": wheel_targets(contract, name.removeprefix("wheel-"))}
    raise ContractError(f"unknown matrix name {name!r}, expected one of {_EMITTABLE_MATRICES}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT_PATH)
    parser.add_argument("--validate", action="store_true", help="validate the contract and exit")
    parser.add_argument("--digest", action="store_true", help="print the contract's SHA-256 digest and exit")
    parser.add_argument(
        "--emit-matrix",
        choices=_EMITTABLE_MATRICES,
        help="print one workflow's build matrix as compact JSON (for GitHub Actions fromJSON) and exit",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.digest:
        print(contract_digest(args.contract))
        return 0

    if args.emit_matrix:
        contract = load_contract(args.contract)
        print(json.dumps(emit_matrix(contract, args.emit_matrix), separators=(",", ":")))
        return 0

    contract = load_contract(args.contract)
    failures = validate(contract)
    if failures:
        print("Platform contract is invalid:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Platform contract is valid: {len(cells(contract))} cells.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
