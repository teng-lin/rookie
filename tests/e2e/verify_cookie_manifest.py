#!/usr/bin/env python3
"""Command-line adapter for the independent cookie manifest verifier."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from cookie_manifest import (
    ManifestError,
    PROJECTIONS,
    load_manifest,
    send_view_manifest,
    verify_records,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--projection", required=True, choices=PROJECTIONS)
    parser.add_argument("--surface", required=True)
    parser.add_argument(
        "--send-view",
        help=(
            "Compare against one named expected_send_views entry instead of "
            "the whole snapshot."
        ),
    )
    args = parser.parse_args()
    try:
        actual = json.load(sys.stdin)
        manifest = load_manifest(args.manifest)
        if args.send_view is not None:
            manifest = send_view_manifest(manifest, args.send_view)
        count = verify_records(
            manifest,
            args.projection,
            actual,
            surface=args.surface,
        )
    except (ManifestError, OSError, json.JSONDecodeError) as error:
        print(f"cookie manifest verification failed: {error}", file=sys.stderr)
        return 1
    scope = f" send view {args.send_view}" if args.send_view else ""
    print(f"{args.surface}: exact {args.projection}{scope} verified ({count} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
