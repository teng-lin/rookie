#!/usr/bin/env python3
"""Thin process boundary for the cross-surface report contract gate."""

import json
import sys

import rookie_cookies


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "profiles":
        value = rookie_cookies.browser_profiles(args[1])
    elif len(args) in (2, 3) and args[0] == "report":
        profile = args[2] if len(args) == 3 else None
        value = rookie_cookies.browser_report(args[1], profile_id=profile)
    elif args == ["load-report"]:
        value = rookie_cookies.load_report()
    else:
        raise SystemExit(
            "usage: report_surface_python.py profiles BROWSER | "
            "report BROWSER [PROFILE] | load-report"
        )
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
