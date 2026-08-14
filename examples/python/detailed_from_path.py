"""Print Firefox cookies together with container/origin context."""

from __future__ import annotations

import sys

import rookie_cookies


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: detailed_from_path.py <cookies.sqlite>", file=sys.stderr)
        return 2
    for record in rookie_cookies.firefox_based_detailed(sys.argv[1]):
        print(record["cookie"]["name"], record["context"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
