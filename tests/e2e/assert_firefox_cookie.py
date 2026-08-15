"""Assert that rookie_cookies can extract the `rookie_ci=bar` cookie from the
Firefox profile seeded earlier in the same CI job.

Driven by env vars:
  ROOKIE_E2E_FIREFOX_PROFILE  required — same path passed to the seed step
  ROOKIE_E2E_DOMAIN           optional — domain filter (default: 127.0.0.1)
  ROOKIE_E2E_COOKIE_NAME      optional — expected name (default: rookie_ci)
  ROOKIE_E2E_COOKIE_VALUE     optional — expected value (default: bar)
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import rookie_cookies


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

    cookies = rookie_cookies.cookies_from_path(str(db_path), [domain])
    legacy = rookie_cookies.firefox_based(str(db_path), [domain])
    detailed = rookie_cookies.firefox_based_detailed(str(db_path), [domain])

    expected_name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    expected_value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    seeded = next((c for c in cookies if c["name"] == expected_name), None)
    if seeded is None:
        print(
            f"seeded cookie {expected_name!r} not found among {len(cookies)} cookies "
            f"for domain {domain}",
            file=sys.stderr,
        )
        return 1

    if seeded["value"] != expected_value:
        print(
            f"cookie value mismatch: expected {expected_value!r}, "
            f"got {seeded['value']!r}",
            file=sys.stderr,
        )
        return 1

    if legacy != cookies:
        print("legacy firefox_based disagrees with cookies_from_path", file=sys.stderr)
        return 1

    now = int(time.time())
    expires = seeded.get("expires")
    if not isinstance(expires, int) or not now < expires <= now + 7_200:
        print(
            "Firefox expiry must be Unix seconds near the seeded Max-Age: "
            f"got {expires!r} at {now}",
            file=sys.stderr,
        )
        return 1

    detailed_seeded = next(
        (record for record in detailed if record["cookie"]["name"] == expected_name),
        None,
    )
    if detailed_seeded is None or "origin_attributes" not in detailed_seeded["context"]:
        print("detailed Firefox binding omitted the seeded cookie context", file=sys.stderr)
        return 1

    print(
        f"rookie_cookies ({sys.platform}, firefox): "
        f"{expected_name}={expected_value} verified "
        f"({len(cookies)} cookies for {domain})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
