"""Assert that rookie_cookies can extract the `rookie_ci=bar` cookie from the
Chrome profile seeded earlier in the same CI job.

Driven by env vars:
  ROOKIE_E2E_USER_DATA_DIR  required — same path passed to the seed step
  ROOKIE_E2E_COOKIE_DB      optional — explicit DB override
  ROOKIE_E2E_DOMAIN         optional — domain filter (default: 127.0.0.1)
  ROOKIE_E2E_COOKIE_NAME    optional — expected name (default: rookie_ci)
  ROOKIE_E2E_COOKIE_VALUE   optional — expected value (default: bar)
  ROOKIE_E2E_DISCOVERY_*    optional — separate name/value for chrome discovery

Designed to be run on Linux/macOS/Windows. On Linux this runs inside the same
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
    db_override = os.environ.get("ROOKIE_E2E_COOKIE_DB")
    db_path = Path(db_override) if db_override else find_cookie_db(user_data_dir)

    # The explicit allow_elevated_fallback is deliberate and is NOT what the
    # default does. The 0.6 default is injection_only, so these calls would
    # decrypt v20 without it; pinning the most permissive policy is what keeps
    # this canary a test of *elevated* recovery specifically, on a runner
    # where unprivileged injection may not be enough. chromium_based is the
    # deprecated bridge and keeps allow_elevated_fallback unconditionally.
    #
    # Consequence worth knowing: because this pins a policy, nothing here
    # exercises the default. That is covered by
    # `chromium_platform_keys::windows::tests::
    # the_policy_decides_whether_v20_metadata_is_even_attempted`, since this
    # workflow does not run on pull requests. See CHANGELOG.md.
    if sys.platform == "win32":
        key_path = user_data_dir / "Local State"
        canonical = rookie_cookies.chromium_cookies_from_path(
            str(db_path),
            {
                "domains": [domain],
                "local_state_path": str(key_path),
                "app_bound": "allow_elevated_fallback",
            },
        )
        legacy = rookie_cookies.chromium_based(
            str(key_path), str(db_path), [domain]
        )
        results = [
            ("chromium_cookies_from_path(LocalStateFile)", canonical),
            ("chromium_based", legacy),
        ]
    else:
        automatic = rookie_cookies.chromium_cookies_from_path(
            str(db_path),
            {"domains": [domain], "app_bound": "allow_elevated_fallback"},
        )
        browser_id = os.environ.get("ROOKIE_E2E_BROWSER_ID", "chrome")
        canonical = rookie_cookies.chromium_cookies_from_path(
            str(db_path),
            {
                "domains": [domain],
                "browser_id": browser_id,
                "app_bound": "allow_elevated_fallback",
            },
        )
        legacy = rookie_cookies.chromium_based(str(db_path), [domain], browser_id)
        results = [
            ("chromium_cookies_from_path(Automatic)", automatic),
            ("chromium_cookies_from_path(BrowserId)", canonical),
            ("chromium_based", legacy),
        ]

    expected_name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    expected_value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    results = [
        (surface, cookies, expected_name, expected_value)
        for surface, cookies in results
    ]
    if os.environ.get("ROOKIE_E2E_CHECK_BROWSER_DISCOVERY") == "1":
        discovery_name = os.environ.get(
            "ROOKIE_E2E_DISCOVERY_COOKIE_NAME", expected_name
        )
        discovery_value = os.environ.get(
            "ROOKIE_E2E_DISCOVERY_COOKIE_VALUE", expected_value
        )
        browser_name = os.environ.get("ROOKIE_E2E_TARGET_BROWSER", "chrome").lower()
        browser_fns = {
            "chrome": rookie_cookies.chrome,
            "google-chrome": rookie_cookies.chrome,
            "edge": rookie_cookies.edge,
            "msedge": rookie_cookies.edge,
            "brave": rookie_cookies.brave,
        }
        browser_fn = browser_fns.get(browser_name)
        if browser_fn is None:
            print(
                f"unsupported ROOKIE_E2E_TARGET_BROWSER {browser_name!r}",
                file=sys.stderr,
            )
            return 2
        results.append(
            (browser_name, browser_fn([domain]), discovery_name, discovery_value)
        )

    for surface, result, surface_name, surface_value in results:
        seeded = next((c for c in result if c["name"] == surface_name), None)
        if seeded is None:
            print(
                f"{surface}: seeded cookie {surface_name!r} not found among "
                f"{len(result)} cookies for domain {domain}",
                file=sys.stderr,
            )
            return 1
        if seeded["value"] != surface_value:
            print(
                f"{surface}: cookie value mismatch: expected {surface_value!r}, "
                f"got {seeded['value']!r}",
                file=sys.stderr,
            )
            return 1

    print(
        f"rookie_cookies ({sys.platform}): "
        f"{expected_name}={expected_value} verified "
        f"({len(results[0][1])} cookies for {domain}; "
        f"surfaces: {', '.join(surface for surface, *_ in results)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
