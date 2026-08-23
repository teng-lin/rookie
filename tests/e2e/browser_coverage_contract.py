"""Machine-readable depth contract shared by browser E2E runners.

The coverage manifest describes both where a browser cell runs and how deeply
that cell is asserted.  Runners record capabilities only after their
corresponding assertion succeeds, then call :func:`assert_observed_depth` so a
manifest claim cannot silently get ahead of the executable harness.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Iterable, Mapping


COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
DEPTH_LEVELS = frozenset({"none", "fixture", "live"})
CONVENIENCE_DISPATCHES = frozenset({"chromium", "gecko", "native"})


def load_coverage() -> dict:
    return json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))


def platform_id(system: str | None = None) -> str:
    """Map a ``sys.platform`` string onto a coverage-manifest platform name."""

    system = sys.platform if system is None else system
    if system == "win32":
        return "windows"
    if system == "darwin":
        return "macos"
    return "linux"


def convenience_function(
    browser_name: str,
    dispatch: str,
    document: dict | None = None,
    platform: str | None = None,
) -> dict:
    """Resolve a target-browser name onto its declared convenience contract.

    ``browser_name`` is whatever ``ROOKIE_E2E_TARGET_BROWSER`` carries: a
    registry canonical ID or one of the aliases the manifest declares for it.
    Anything the manifest does not claim raises, which keeps an unrecognised
    target browser a hard failure in the assert scripts rather than a silently
    skipped surface.
    """

    document = document or load_coverage()
    platform = platform_id() if platform is None else platform
    wanted = browser_name.strip().lower()
    for browser_id, entry in document["convenience_functions"].items():
        if wanted != browser_id and wanted not in entry["aliases"]:
            continue
        if entry["dispatch"] != dispatch:
            raise AssertionError(
                f"{browser_id} declares the {entry['dispatch']!r} dispatch family, "
                f"not {dispatch!r}"
            )
        if platform not in entry["platforms"]:
            raise AssertionError(
                f"{browser_id} declares no convenience function on {platform}"
            )
        return {"browser_id": browser_id, **entry}
    raise AssertionError(
        f"no convenience function is declared for browser {browser_name!r}"
    )


def coverage_row(platform: str, browser: str, document: dict | None = None) -> dict:
    document = document or load_coverage()
    matches = [
        row
        for row in document["coverage"]
        if row["platform"] == platform and row["browser"] == browser
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected one coverage row for {platform}/{browser}, got {len(matches)}"
        )
    return matches[0]


def depth_for(
    row: Mapping[str, object], document: dict | None = None
) -> dict[str, str]:
    document = document or load_coverage()
    profile_name = row.get("depth_profile")
    try:
        profile = document["depth_profiles"][profile_name]
    except (KeyError, TypeError) as error:
        raise AssertionError(f"unknown depth profile {profile_name!r}") from error
    return dict(profile)


def assert_observed_depth(
    row: Mapping[str, object],
    observed: Mapping[str, str] | Iterable[str],
    document: dict | None = None,
) -> None:
    """Require a runner's successful assertions to equal its declared depth.

    Passing an iterable is shorthand for live observations.  A mapping is
    required by fixture runners, whose successful assertions have fixture
    rather than live-browser provenance.
    """

    expected = depth_for(row, document)
    if isinstance(observed, Mapping):
        actual = {name: level for name, level in observed.items()}
    else:
        actual = {name: "live" for name in observed}

    unknown = set(actual) - set(expected)
    if unknown:
        raise AssertionError(
            f"runner recorded unknown depth capabilities: {sorted(unknown)}"
        )
    normalized = {name: actual.get(name, "none") for name in expected}
    if normalized != expected:
        differences = {
            name: {"declared": expected[name], "observed": normalized[name]}
            for name in expected
            if expected[name] != normalized[name]
        }
        cell = f"{row.get('platform')}/{row.get('browser')}"
        raise AssertionError(f"depth claim mismatch for {cell}: {differences}")


def emit_representative_depth(
    lane_name: str,
    capabilities: Iterable[str],
    surfaces: Iterable[str],
    document: dict | None = None,
) -> None:
    """Validate and emit a receipt only after a representative lane succeeds."""

    document = document or load_coverage()
    try:
        lane = document["representative_depth_lanes"][lane_name]
    except KeyError as error:
        raise AssertionError(
            f"unknown representative depth lane {lane_name!r}"
        ) from error
    actual_capabilities = sorted(set(capabilities))
    actual_surfaces = sorted(set(surfaces))
    expected_capabilities = sorted(lane["capabilities"])
    expected_surfaces = sorted(lane["surfaces"])
    if (
        actual_capabilities != expected_capabilities
        or actual_surfaces != expected_surfaces
    ):
        raise AssertionError(
            f"representative depth mismatch for {lane_name}: "
            f"capabilities={actual_capabilities} expected={expected_capabilities}; "
            f"surfaces={actual_surfaces} expected={expected_surfaces}"
        )
    print(
        "E2E_DEPTH_RECEIPT "
        + json.dumps(
            {
                "lane": lane_name,
                "capabilities": actual_capabilities,
                "surfaces": actual_surfaces,
            },
            sort_keys=True,
        ),
        flush=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and emit one representative browser-depth receipt."
    )
    parser.add_argument("lane")
    parser.add_argument("--capability", action="append", default=[])
    parser.add_argument("--surface", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        emit_representative_depth(args.lane, args.capability, args.surface)
    except (AssertionError, KeyError, OSError, TypeError, json.JSONDecodeError) as error:
        print(f"browser depth receipt failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
