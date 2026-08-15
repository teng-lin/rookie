#!/usr/bin/env python3
"""Write deterministic checksums for release artifacts awaiting malware scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


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
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()

    if not VERSION_PATTERN.fullmatch(args.version):
        parser.error(f"invalid release version: {args.version!r}")
    if not COMMIT_PATTERN.fullmatch(args.source_sha):
        parser.error("source SHA must be a lowercase 40-character commit SHA")

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
        records.append(
            {
                "bytes": path.stat().st_size,
                "path": relative.as_posix(),
                "sha256": sha256(path),
            }
        )

    document = {
        "schema_version": 1,
        "release": {
            "source_sha": args.source_sha,
            "tag": f"v{args.version}",
            "version": args.version,
        },
        "artifacts": sorted(records, key=lambda record: str(record["path"])),
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
