"""Assert that rookiepy can extract the `rookie_ci=bar` cookie from the
Firefox profile seeded earlier in the same CI job.

Driven by env vars:
  ROOKIE_E2E_FIREFOX_PROFILE  required — same path passed to the seed step
  ROOKIE_E2E_DOMAIN           optional — domain filter (default: 127.0.0.1)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import rookiepy


def main() -> int:
    try:
        profile_dir = Path(os.environ["ROOKIE_E2E_FIREFOX_PROFILE"])
    except KeyError:
        print("ROOKIE_E2E_FIREFOX_PROFILE must be set", file=sys.stderr)
        return 2

    domain = os.environ.get("ROOKIE_E2E_DOMAIN", "127.0.0.1")
    db_path = profile_dir / "cookies.sqlite"

    if not db_path.exists():
        print(f"no cookies.sqlite under {profile_dir}", file=sys.stderr)
        return 1

    cookies = rookiepy.firefox_based(str(db_path), [domain])

    seeded = next((c for c in cookies if c["name"] == "rookie_ci"), None)
    if seeded is None:
        print(
            f"seeded cookie `rookie_ci` not found among {len(cookies)} cookies "
            f"for domain {domain}",
            file=sys.stderr,
        )
        return 1

    if seeded["value"] != "bar":
        print(
            f"cookie value mismatch: expected 'bar', got {seeded['value']!r}",
            file=sys.stderr,
        )
        return 1

    print(
        f"rookiepy ({sys.platform}, firefox): "
        f"rookie_ci=bar verified ({len(cookies)} cookies for {domain})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
