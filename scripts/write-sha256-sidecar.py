#!/usr/bin/env python3
"""Write a portable sha256sum-compatible sidecar for one artifact."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sidecar(artifact: Path) -> Path:
    if not artifact.is_file():
        raise ValueError(f"artifact is not a regular file: {artifact}")
    if "\n" in artifact.name or "\r" in artifact.name:
        raise ValueError("artifact name must not contain a newline")

    sidecar = artifact.with_name(f"{artifact.name}.sha256")
    line = f"{sha256(artifact)}  {artifact.name}\n"
    sidecar.write_bytes(line.encode("ascii"))
    return sidecar


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()

    print(write_sidecar(args.artifact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
