#!/usr/bin/env python3
"""Copy the repo LICENSE.md into npm package directories for `npm pack`.

Those copies are gitignored. `npm pack --ignore-scripts` (used by publish-npm
and package-npm-tarballs.py) cannot run a prepack hook, so packers must call
this first.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil


REPO = Path(__file__).resolve().parents[1]


def destinations(node_root: Path) -> list[Path]:
    dests = [node_root / "LICENSE.md"]
    npm_root = node_root / "npm"
    if npm_root.is_dir():
        for package in sorted(npm_root.iterdir()):
            if (package / "package.json").is_file():
                dests.append(package / "LICENSE.md")
    return dests


def sync_node_license(node_root: Path, source: Path | None = None) -> list[Path]:
    license_src = source or (REPO / "LICENSE.md")
    if not license_src.is_file():
        raise FileNotFoundError(f"missing license source: {license_src}")
    written: list[Path] = []
    for dest in destinations(node_root):
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(license_src, dest)
        written.append(dest)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--node-root",
        type=Path,
        default=REPO / "bindings" / "node",
    )
    args = parser.parse_args()
    for path in sync_node_license(args.node_root.resolve()):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
