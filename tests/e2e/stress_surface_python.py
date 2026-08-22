#!/usr/bin/env python3
"""Emit one explicit-path snapshot as JSON for the stress verifier."""

from __future__ import annotations

import argparse
import json

import rookie_cookies


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--database", required=True)
    parser.add_argument("--browser-id", default="chromium")
    parser.add_argument(
        "--projection", choices=("unfiltered_flat", "detailed"), required=True
    )
    args = parser.parse_args()
    if args.engine == "chromium":
        snapshot = rookie_cookies.from_path(args.database, browser_id=args.browser_id)
    else:
        snapshot = rookie_cookies.from_path(args.database)
    records = (
        snapshot.as_list()
        if args.projection == "unfiltered_flat"
        else snapshot.detailed_cookies()
    )
    print(json.dumps(records, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
