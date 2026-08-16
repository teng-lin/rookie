#!/usr/bin/env python3
"""Write deterministic checksums for release artifacts awaiting malware scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jcs  # noqa: E402
import platform_contract  # noqa: E402


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument(
        "--controller-sha",
        required=True,
        help="commit of the coordinator workflow that produced this manifest",
    )
    parser.add_argument(
        "--platform-contract-digest",
        required=True,
        help="SHA-256 of release/platform-contract.json at the pinned commit",
    )
    parser.add_argument(
        "--platform-contract",
        type=Path,
        default=platform_contract.DEFAULT_CONTRACT_PATH,
        help="path to platform-contract.json, for matching each artifact to its cell's helper_roles",
    )
    parser.add_argument(
        "--kind",
        choices=("release", "candidate"),
        default="release",
        help=(
            "'release' (default) for a real, publishable bundle; 'candidate' "
            "for a PR-time bundle assembled the same way but never published "
            "-- see release-hardening program R4"
        ),
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()

    if not VERSION_PATTERN.fullmatch(args.version):
        parser.error(f"invalid release version: {args.version!r}")
    if not COMMIT_PATTERN.fullmatch(args.source_sha):
        parser.error("source SHA must be a lowercase 40-character commit SHA")
    if not COMMIT_PATTERN.fullmatch(args.controller_sha):
        parser.error("controller SHA must be a lowercase 40-character commit SHA")
    if not re.fullmatch(r"[0-9a-f]{64}", args.platform_contract_digest):
        parser.error("platform contract digest must be a lowercase 64-character SHA-256 hex digest")

    contract = platform_contract.load_contract(args.platform_contract)

    root = args.root.resolve(strict=True)
    records: list[dict[str, object]] = []
    seen: set[Path] = set()
    for supplied in args.artifacts:
        if supplied.is_symlink():
            parser.error(f"artifact must not be a symlink: {supplied}")
        path = supplied.resolve(strict=True)
        if path in seen:
            parser.error(f"duplicate artifact: {supplied}")
        seen.add(path)
        if not path.is_file():
            parser.error(f"artifact must be a regular file: {supplied}")
        try:
            relative = path.relative_to(root)
        except ValueError:
            parser.error(f"artifact is outside manifest root: {supplied}")

        # Ties this artifact's digest to the exact helper roles it was built
        # with, per platform-contract.json's `helper_roles` for the matching
        # cell -- this is what makes "client + every enabled helper role" one
        # digest-identified unit instead of an implicit assumption (issue
        # #241, workstream E). Fails closed: an artifact this contract has no
        # cell for is exactly the drift this manifest exists to catch, not
        # something to record silently with an empty role list.
        try:
            cell = platform_contract.match_cell_for_artifact(contract, path.name)
        except platform_contract.ArtifactMatchError as error:
            parser.error(str(error))
        if cell is None:
            parser.error(
                f"artifact {path.name!r} does not match any cell in {args.platform_contract} "
                "(see platform_contract.py's match_cell_for_artifact)"
            )

        records.append(
            {
                "bytes": path.stat().st_size,
                "path": relative.as_posix(),
                "sha256": sha256(path),
                "helper_roles": sorted(cell.get("helper_roles", [])),
            }
        )

    release = {
        "source_sha": args.source_sha,
        "controller_sha": args.controller_sha,
        "platform_contract_digest": args.platform_contract_digest,
        "tag": f"v{args.version}",
        "version": args.version,
        # 'release' for a real, publishable bundle; 'candidate' for a PR-time
        # bundle assembled the same way but never published -- distinguishes
        # the two at read time so nothing downstream can confuse one for the
        # other (release-hardening program R4).
        "kind": args.kind,
    }
    artifacts = sorted(records, key=lambda record: str(record["path"]))

    # A whole-manifest digest, over everything above plus `artifacts`,
    # computed via RFC 8785 JCS so it reproduces identically regardless of
    # field insertion order or which host wrote the file. Computed before
    # `manifest_digest` itself is added to `release`, so the digest only
    # ever covers content that exists independent of the digest -- it cannot
    # cover itself.
    manifest_digest = jcs.digest({"release": release, "artifacts": artifacts})
    release["manifest_digest"] = manifest_digest

    document = {
        # v4 adds `release.kind` and `release.manifest_digest` (release-
        # hardening program R4). v3 added `helper_roles` to each artifact
        # record, matched against platform-contract.json (v2 added
        # controller_sha and platform_contract_digest to `release`).
        # `registry_digest` on artifacts is deliberately not populated here:
        # a registry's own digest (npm `dist.integrity`, a PyPI wheel hash,
        # a crates.io checksum) isn't known until after that artifact is
        # actually published, so it can't be in a manifest written before
        # publication. Reconciling pre/post-publish digests is out of scope
        # for this manifest — see the release-hardening program's R6 phase.
        "schema_version": 4,
        "release": release,
        "artifacts": artifacts,
    }
    output = args.output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        parser.error("output is outside manifest root")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
