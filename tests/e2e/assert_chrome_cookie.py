"""Assert exact rookie_cookies output for the seeded Chromium profile.

Ordinary hosted lanes consume the corpus manifest. Focused canaries that set a
non-default expected cookie retain the legacy name/value assertion.

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

from cookie_manifest import find_manifest, load_manifest, verify_records
from cookie_state import assert_cookie_state, state_from_environment


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
    expected_name = os.environ.get("ROOKIE_E2E_COOKIE_NAME", "rookie_ci")
    expected_value = os.environ.get("ROOKIE_E2E_COOKIE_VALUE", "bar")
    manifest_path = find_manifest(user_data_dir, expected_name=expected_name)
    manifest = load_manifest(manifest_path) if manifest_path else None
    state_configured = any(
        name in os.environ
        for name in (
            "ROOKIE_E2E_REQUIRED_COOKIES_JSON",
            "ROOKIE_E2E_FORBIDDEN_COOKIES_JSON",
            "ROOKIE_E2E_EXACT_COOKIE_STATE",
        )
    )
    recommended_snapshot = None

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
    # the_policy_decides_whether_v20_metadata_is_even_attempted`. This Windows
    # branch remains trusted-ref-only even though Linux Chrome now gates pull
    # requests. See CHANGELOG.md.
    if sys.platform == "win32":
        key_path = user_data_dir / "Local State"
        canonical = rookie_cookies.extract_from_path(
            str(db_path),
            domains=[domain],
            local_state_path=str(key_path),
            app_bound="allow_elevated_fallback",
        )
        legacy = rookie_cookies.chromium_based(str(key_path), str(db_path), [domain])
        direct_snapshot = rookie_cookies.from_path(
            str(db_path),
            local_state_path=str(key_path),
            app_bound="allow_elevated_fallback",
        )
        results = [
            ("extract_from_path(LocalStateFile)", canonical, "filtered_flat"),
            ("chromium_based", legacy, "filtered_flat"),
        ]
    else:
        browser_id = os.environ.get("ROOKIE_E2E_BROWSER_ID", "chrome")
        canonical = rookie_cookies.extract_from_path(
            str(db_path),
            domains=[domain],
            browser_id=browser_id,
            app_bound="allow_elevated_fallback",
        )
        legacy = rookie_cookies.chromium_based(str(db_path), [domain], browser_id)
        direct_snapshot = rookie_cookies.from_path(
            str(db_path),
            browser_id=browser_id,
            app_bound="allow_elevated_fallback",
        )
        results = [
            ("extract_from_path(BrowserId)", canonical, "filtered_flat"),
            ("chromium_based", legacy, "filtered_flat"),
        ]

    if direct_snapshot.browser_id is not None or direct_snapshot.profile_id is not None:
        print("from_path unexpectedly reported a discovered identity", file=sys.stderr)
        return 1
    direct_detailed = direct_snapshot.detailed_cookies()
    if not any(record["cookie"]["name"] == expected_name for record in direct_detailed):
        print("from_path.detailed_cookies omitted the seeded cookie", file=sys.stderr)
        return 1
    results.append(
        ("from_path.detailed_cookies", direct_snapshot.as_list(), "unfiltered_flat")
    )

    results = [
        (surface, cookies, projection, expected_name, expected_value)
        for surface, cookies, projection in results
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
            (
                browser_name,
                browser_fn([domain]),
                "filtered_flat",
                discovery_name,
                discovery_value,
            )
        )

    if os.environ.get("ROOKIE_E2E_CHECK_RECOMMENDED_READ") == "1":
        browser_id = os.environ.get("ROOKIE_E2E_BROWSER_ID", "chrome")
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
        if identity["browser_id"] != browser_id:
            print(
                f"discovery returned wrong browser identity: {identity!r}",
                file=sys.stderr,
            )
            return 1
        expected_profile_id = os.environ.get("ROOKIE_E2E_EXPECTED_PROFILE_ID")
        if (
            expected_profile_id is not None
            and identity["profile_id"] != expected_profile_id
        ):
            print(
                "discovery returned the wrong independently expected profile ID: "
                f"expected {expected_profile_id}, got {identity['profile_id']}",
                file=sys.stderr,
            )
            return 1
        recommended_snapshot = rookie_cookies.read(
            browser=browser_id,
            profile=identity["profile_id"],
            app_bound="allow_elevated_fallback",
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
        if not any(
            record["cookie"]["name"] == expected_name
            for record in recommended_snapshot.detailed_cookies()
        ):
            print(
                "recommended read detailed output omitted the seeded cookie",
                file=sys.stderr,
            )
            return 1
        results.append(
            (
                "read(profile).detailed_cookies",
                recommended_snapshot.as_list(),
                "unfiltered_flat",
                expected_name,
                expected_value,
            )
        )

    for surface, result, projection, surface_name, surface_value in results:
        if manifest is not None and not state_configured:
            verify_records(
                manifest,
                projection,
                result,
                surface=f"Python {surface}",
            )
            continue
        try:
            required, forbidden = state_from_environment(surface_name, surface_value)
            assert_cookie_state(result, required, forbidden, surface=surface)
        except (AssertionError, ValueError) as error:
            print(error, file=sys.stderr)
            return 1

    if manifest is not None and not state_configured:
        verify_records(
            manifest,
            "detailed",
            direct_detailed,
            surface="Python from_path.detailed_cookies",
        )
        if recommended_snapshot is not None:
            verify_records(
                manifest,
                "detailed",
                recommended_snapshot.detailed_cookies(),
                surface="Python read(profile).detailed_cookies",
            )

    print(
        f"rookie_cookies ({sys.platform}): "
        f"{'exact cookie corpus' if manifest is not None else f'{expected_name}={expected_value}'} verified "
        f"({len(results[0][1])} cookies for {domain}; "
        f"surfaces: {', '.join(surface for surface, *_ in results)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
