"""Assert that rookie_cookies can extract the `rookie_ci=bar` cookie from the
Chrome profile seeded earlier in the same CI job.

Driven by env vars:
  ROOKIE_E2E_USER_DATA_DIR  required — same path passed to the seed step
  ROOKIE_E2E_DOMAIN         optional — domain filter (default: 127.0.0.1)
  ROOKIE_E2E_COOKIE_NAME    optional — expected name (default: rookie_ci)
  ROOKIE_E2E_COOKIE_VALUE   optional — expected value (default: bar)

Designed to be run on Linux/macOS/Windows (rookie_cookies's chromium_based
binding handles the per-OS crypto). On Linux this runs inside the same
dbus-run-session as the Rust test so libsecret is reachable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import rookie_cookies


def find_cookie_db(user_data_dir: Path) -> Path:
    default_dir = user_data_dir / "Default"
    for rel in ("Network/Cookies", "Cookies"):
        candidate = default_dir / rel
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        f"no cookie db under {default_dir} "
        "(tried Default/Network/Cookies and Default/Cookies)"
    )


def main() -> int:
    try:
        user_data_dir = Path(os.environ["ROOKIE_E2E_USER_DATA_DIR"])
    except KeyError:
        print("ROOKIE_E2E_USER_DATA_DIR must be set", file=sys.stderr)
        return 2

    domain = os.environ.get("ROOKIE_E2E_DOMAIN", "127.0.0.1")
    db_path = find_cookie_db(user_data_dir)

    if sys.platform == "win32":
        # Windows binding takes (key_path, db_path, domains)
        key_path = user_data_dir / "Local State"
        cookies = rookie_cookies.chromium_based(str(key_path), str(db_path), [domain])
    else:
        cookies = rookie_cookies.chromium_based(str(db_path), [domain])

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

    print(
        f"rookie_cookies ({sys.platform}): "
        f"{expected_name}={expected_value} verified "
        f"({len(cookies)} cookies for {domain})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
