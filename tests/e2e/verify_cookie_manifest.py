#!/usr/bin/env python3
"""Command-line adapter for the independent cookie manifest verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cookie_manifest import ManifestError, PROJECTIONS, load_manifest, verify_records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--projection", required=True, choices=PROJECTIONS)
    parser.add_argument("--surface", required=True)
    args = parser.parse_args()
    try:
        actual = json.load(sys.stdin)
        count = verify_records(
            load_manifest(args.manifest),
            args.projection,
            actual,
            surface=args.surface,
        )
    except (ManifestError, OSError, json.JSONDecodeError) as error:
        print(f"cookie manifest verification failed: {error}", file=sys.stderr)
        return 1
    print(f"{args.surface}: exact {args.projection} verified ({count} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
