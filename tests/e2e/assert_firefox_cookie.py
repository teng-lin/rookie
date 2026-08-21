"""Assert exact rookie_cookies output for the seeded Firefox profile.

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

from cookie_manifest import find_manifest, load_manifest, verify_records
from cookie_state import assert_cookie_state, state_from_environment


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
    detailed = rookie_cookies.firefox_based_detailed(str(db_path), None)
    direct_snapshot = rookie_cookies.from_path(str(db_path))
    direct_detailed = direct_snapshot.detailed_cookies()
    if direct_snapshot.browser_id is not None or direct_snapshot.profile_id is not None:
        print("from_path unexpectedly reported a discovered identity", file=sys.stderr)
        return 1

    expected_name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    expected_value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    manifest_path = find_manifest(profile_dir, expected_name=expected_name)
    manifest = load_manifest(manifest_path) if manifest_path is not None else None
    recommended_snapshot = None
    if manifest_path is not None:
        verify_records(
            manifest, "filtered_flat", cookies, surface="Python cookies_from_path"
        )
        verify_records(
            manifest, "filtered_flat", legacy, surface="Python firefox_based"
        )
        verify_records(
            manifest,
            "detailed",
            detailed,
            surface="Python firefox_based_detailed",
        )
        verify_records(
            manifest,
            "detailed",
            direct_detailed,
            surface="Python from_path.detailed_cookies",
        )
    else:
        try:
            required, forbidden = state_from_environment(expected_name, expected_value)
            assert_cookie_state(cookies, required, forbidden, surface="cookies_from_path")
            assert_cookie_state(legacy, required, forbidden, surface="firefox_based")
            assert_cookie_state(
                [record["cookie"] for record in detailed],
                required,
                forbidden,
                surface="firefox_based_detailed",
            )
            assert_cookie_state(
                [record["cookie"] for record in direct_detailed],
                required,
                forbidden,
                surface="from_path.detailed_cookies",
            )
        except (AssertionError, ValueError) as error:
            print(error, file=sys.stderr)
            return 1

        seeded = next(c for c in cookies if c["name"] == expected_name)

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

        direct_seeded = next(
            (
                record
                for record in direct_detailed
                if record["cookie"]["name"] == expected_name
            ),
            None,
        )
        if direct_seeded is None or direct_seeded["cookie"]["value"] != expected_value:
            print("from_path.detailed_cookies omitted the seeded cookie", file=sys.stderr)
            return 1

    recommended_checked = os.environ.get("ROOKIE_E2E_CHECK_RECOMMENDED_READ") == "1"
    if recommended_checked:
        browser_id = os.environ.get("ROOKIE_E2E_BROWSER_ID", "firefox")
        profiles = rookie_cookies.browser_profiles(browser_id)
        matching_profiles = [
            profile
            for profile in profiles
            if any(
                Path(source["path"]).resolve() == db_path.resolve()
                for source in profile["sources"]
            )
        ]
        if len(matching_profiles) != 1:
            print(
                f"{browser_id} discovery found {len(matching_profiles)} profiles "
                f"for source {db_path}; profiles={profiles!r}",
                file=sys.stderr,
            )
            return 1
        identity = matching_profiles[0]["profile"]
        recommended_snapshot = rookie_cookies.read(
            browser=browser_id, profile=identity["profile_id"]
        )
        if (
            recommended_snapshot.browser_id != browser_id
            or recommended_snapshot.profile_id != identity["profile_id"]
        ):
            print(
                "recommended read returned the wrong browser/profile identity",
                file=sys.stderr,
            )
            return 1
        recommended = next(
            (
                record
                for record in recommended_snapshot.detailed_cookies()
                if record["cookie"]["name"] == expected_name
            ),
            None,
        )
        if recommended is None or recommended["cookie"]["value"] != expected_value:
            print("recommended read detailed output omitted the seeded cookie", file=sys.stderr)
            return 1
        if manifest is not None:
            verify_records(
                manifest,
                "detailed",
                recommended_snapshot.detailed_cookies(),
                surface="Python read(profile).detailed_cookies",
            )

    print(
        f"rookie_cookies ({sys.platform}, firefox): "
        f"{'exact cookie corpus' if manifest is not None else f'{expected_name}={expected_value}'} verified "
        f"({len(cookies)} cookies for {domain}; explicit detailed verified"
        f"{'; recommended read verified' if recommended_checked else ''})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
