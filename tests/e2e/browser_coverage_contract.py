"""Machine-readable depth contract shared by browser E2E runners.

The coverage manifest describes both where a browser cell runs and how deeply
that cell is asserted.  Runners record capabilities only after their
corresponding assertion succeeds, then call :func:`assert_observed_depth` so a
manifest claim cannot silently get ahead of the executable harness.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping


COVERAGE_PATH = Path(__file__).with_name("browser_coverage.json")
DEPTH_LEVELS = frozenset({"none", "fixture", "live"})


def load_coverage() -> dict:
    return json.loads(COVERAGE_PATH.read_text(encoding="utf-8"))


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


def depth_for(row: Mapping[str, object], document: dict | None = None) -> dict[str, str]:
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
        raise AssertionError(f"runner recorded unknown depth capabilities: {sorted(unknown)}")
    normalized = {name: actual.get(name, "none") for name in expected}
    if normalized != expected:
        differences = {
            name: {"declared": expected[name], "observed": normalized[name]}
            for name in expected
            if expected[name] != normalized[name]
        }
        cell = f"{row.get('platform')}/{row.get('browser')}"
        raise AssertionError(f"depth claim mismatch for {cell}: {differences}")
