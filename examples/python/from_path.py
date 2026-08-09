"""Minimal example: read cookies from an explicit Firefox-style
`cookies.sqlite` and print each one.

Run with:
    python examples/python/from_path.py /path/to/cookies.sqlite

On CI this is invoked against the seeded Firefox profile that the e2e
workflow creates, so it doubles as a regression test for the
`rookie_cookies.firefox_based` public API drifting.
"""

from __future__ import annotations

import sys

import rookie_cookies


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: from_path.py <cookies.sqlite>", file=sys.stderr)
        return 2
    db_path = sys.argv[1]
    cookies = rookie_cookies.firefox_based(db_path, None)
    for cookie in cookies:
        print(cookie)
    return 0


if __name__ == "__main__":
    sys.exit(main())
