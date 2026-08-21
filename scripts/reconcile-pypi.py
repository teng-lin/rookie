#!/usr/bin/env python3
"""Reconcile a manifest-verified Python release bundle with PyPI.

This is intentionally fail-closed. Existing PyPI files are accepted only when
their SHA-256 digest matches the exact file recorded in the release manifest.
Files missing from PyPI can be copied into a clean staging directory for a
targeted trusted-publishing retry; mismatched or unexpected files stop the
recovery before any upload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ReconcileError(Exception):
    pass


@dataclass(frozen=True)
class Distribution:
    filename: str
    path: Path
    sha256: str
    size: int


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_expected_distributions(
    manifest_path: Path, artifacts_root: Path, version: str
) -> dict[str, Distribution]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReconcileError(f"could not read {manifest_path}: {error}") from error
    if not isinstance(manifest, dict):
        raise ReconcileError(f"{manifest_path}: manifest must be an object")

    release = manifest.get("release")
    if not isinstance(release, dict):
        raise ReconcileError(f"{manifest_path}: release must be an object")
    if release.get("kind") != "release":
        raise ReconcileError(
            f"{manifest_path}: release.kind must be 'release', got {release.get('kind')!r}"
        )
    if release.get("version") != version:
        raise ReconcileError(
            f"{manifest_path}: release.version {release.get('version')!r} does not match {version!r}"
        )
    if release.get("tag") != f"v{version}":
        raise ReconcileError(
            f"{manifest_path}: release.tag {release.get('tag')!r} does not match 'v{version}'"
        )

    records = manifest.get("artifacts")
    if not isinstance(records, list) or not records:
        raise ReconcileError(f"{manifest_path}: artifacts must be a non-empty array")

    root = artifacts_root.resolve()
    expected: dict[str, Distribution] = {}
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ReconcileError(
                f"{manifest_path}: artifacts[{index}] must be an object"
            )

        path_value = record.get("path")
        if not isinstance(path_value, str):
            raise ReconcileError(
                f"{manifest_path}: artifacts[{index}].path must be a string"
            )
        relative = PurePosixPath(path_value)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[:1] != ("dist",)
        ):
            raise ReconcileError(
                f"{manifest_path}: artifact path must be a relative dist/ path, got {path_value!r}"
            )
        artifact_path = (root / Path(*relative.parts)).resolve()
        try:
            artifact_path.relative_to(root)
        except ValueError as error:
            raise ReconcileError(
                f"{manifest_path}: artifact escapes artifacts root: {path_value}"
            ) from error

        filename = relative.name
        if not (filename.endswith(".whl") or filename.endswith(".tar.gz")):
            raise ReconcileError(
                f"{manifest_path}: not a Python distribution: {filename}"
            )
        if filename in expected:
            raise ReconcileError(
                f"{manifest_path}: duplicate artifact filename: {filename}"
            )
        if not artifact_path.is_file():
            raise ReconcileError(f"missing artifact: {path_value}")

        recorded_sha256 = record.get("sha256")
        recorded_size = record.get("bytes")
        if not isinstance(recorded_sha256, str) or not SHA256_PATTERN.fullmatch(
            recorded_sha256
        ):
            raise ReconcileError(f"{manifest_path}: invalid SHA-256 for {filename}")
        if (
            not isinstance(recorded_size, int)
            or isinstance(recorded_size, bool)
            or recorded_size < 0
        ):
            raise ReconcileError(f"{manifest_path}: invalid byte length for {filename}")

        actual_sha256 = sha256(artifact_path)
        if actual_sha256 != recorded_sha256:
            raise ReconcileError(
                f"SHA-256 mismatch for {filename}: manifest says {recorded_sha256}, got {actual_sha256}"
            )
        actual_size = artifact_path.stat().st_size
        if actual_size != recorded_size:
            raise ReconcileError(
                f"byte length mismatch for {filename}: manifest says {recorded_size}, got {actual_size}"
            )
        expected[filename] = Distribution(
            filename, artifact_path, recorded_sha256, recorded_size
        )

    return expected


def fetch_pypi_release(project: str, version: str) -> dict[str, Any]:
    project_path = urllib.parse.quote(project, safe="")
    version_path = urllib.parse.quote(version, safe="")
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{project_path}/{version_path}/json",
        headers={
            "Accept": "application/json",
            "User-Agent": "rookie-cookies-release-recovery/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"urls": []}
        raise ReconcileError(
            f"PyPI returned HTTP {error.code} for {project} {version}"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise ReconcileError(
            f"could not query PyPI for {project} {version}: {error}"
        ) from error


def published_digests(payload: dict[str, Any]) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise ReconcileError("PyPI response must be an object")
    urls = payload.get("urls")
    if not isinstance(urls, list):
        raise ReconcileError("PyPI response does not contain a urls array")

    published: dict[str, str] = {}
    for index, entry in enumerate(urls):
        if not isinstance(entry, dict):
            raise ReconcileError(f"PyPI urls[{index}] must be an object")
        filename = entry.get("filename")
        digests = entry.get("digests")
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(filename, str) or not filename:
            raise ReconcileError(f"PyPI urls[{index}] has no valid filename")
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ReconcileError(f"PyPI has no valid SHA-256 digest for {filename}")
        if filename in published:
            raise ReconcileError(f"PyPI returned duplicate filename: {filename}")
        published[filename] = digest
    return published


def reconcile(
    expected: dict[str, Distribution], published: dict[str, str]
) -> tuple[list[Distribution], list[Distribution]]:
    unexpected = sorted(set(published) - set(expected))
    if unexpected:
        raise ReconcileError(
            "PyPI contains files outside the original release bundle: "
            + ", ".join(unexpected)
        )

    identical: list[Distribution] = []
    missing: list[Distribution] = []
    for filename in sorted(expected):
        distribution = expected[filename]
        registry_digest = published.get(filename)
        if registry_digest is None:
            missing.append(distribution)
        elif registry_digest != distribution.sha256:
            raise ReconcileError(
                f"PyPI digest mismatch for {filename}: registry has {registry_digest}, "
                f"release bundle has {distribution.sha256}"
            )
        else:
            identical.append(distribution)
    return identical, missing


def stage_missing(distributions: list[Distribution], output_dir: Path) -> None:
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ReconcileError(f"staging path is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise ReconcileError(f"staging directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    for distribution in distributions:
        shutil.copy2(distribution.path, output_dir / distribution.filename)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--artifacts-root", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail if any manifest file is not yet visible on PyPI",
    )
    args = parser.parse_args(argv)

    try:
        expected = load_expected_distributions(
            args.manifest, args.artifacts_root, args.version
        )
        published = published_digests(fetch_pypi_release(args.project, args.version))
        identical, missing = reconcile(expected, published)
        if args.require_complete and missing:
            raise ReconcileError(
                "PyPI is still missing release files: "
                + ", ".join(distribution.filename for distribution in missing)
            )
        if args.output_dir is not None:
            stage_missing(missing, args.output_dir)
    except ReconcileError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    for distribution in identical:
        print(f"present_identical\t{distribution.sha256}\t{distribution.filename}")
    for distribution in missing:
        print(f"absent\t{distribution.sha256}\t{distribution.filename}")
    print(f"PyPI reconciliation: {len(identical)} identical, {len(missing)} missing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
