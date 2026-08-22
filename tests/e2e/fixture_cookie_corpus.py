"""Materialize the shared portable corpus into deterministic SQLite fixtures.

These observations are used only for browser/OS registry rows whose products
cannot be installed and driven safely on a hosted runner.  Live-capable rows
continue to derive their oracle from browser-owned storage metadata.
"""

from __future__ import annotations

from email.utils import parsedate_to_datetime
import time
from typing import Any

from hosted_cookie_corpus import (
    applicable_scenarios,
    corpus_engine,
    expanded_value,
    load_corpus,
)


def _fixture_expiry(
    scenario: dict[str, Any],
    operation: dict[str, Any],
    browser: str,
    now: int,
) -> int | None:
    expected = scenario["expected"]
    window = expected.get("expiry_seconds_from_now_by_browser", {}).get(browser)
    window = window or expected.get("expiry_seconds_from_now")
    if window is not None:
        return now + (int(window["min"]) + int(window["max"])) // 2
    max_age = operation.get("max_age")
    if isinstance(max_age, int) and max_age > 0:
        return now + max_age
    if "expires" in operation:
        return int(parsedate_to_datetime(operation["expires"]).timestamp())
    return None


def portable_fixture_observations(
    *,
    engine: str,
    browser: str,
    platform: str,
    now: int | None = None,
) -> list[dict[str, Any]]:
    """Return every stored portable scenario as a decoder observation."""

    corpus = load_corpus()
    corpus_name = corpus_engine(engine)
    generated_at = int(time.time()) if now is None else now
    observations = []
    for scenario in applicable_scenarios(corpus, corpus_name, platform):
        if not scenario["expected"]["stored"]:
            continue
        operation = scenario["operations"][-1]
        hostname = corpus["origins"][scenario["origin"]]["hostname"]
        observations.append(
            {
                "domain": str(operation.get("domain", hostname)),
                "path": str(operation.get("path", "/")),
                "name": str(operation["name"]),
                "observed_value": expanded_value(operation),
                "secure": bool(operation.get("secure")),
                "http_only": bool(operation.get("http_only")),
                "same_site": int(scenario["expected"]["same_site"][corpus_name]),
                "expires": _fixture_expiry(scenario, operation, browser, generated_at),
                "context": {
                    "top_frame_site_key": None,
                    "has_cross_site_ancestor": None,
                    "source_scheme": None,
                    "source_port": None,
                    "is_persistent": None,
                    "origin_attributes": "" if corpus_name == "firefox" else None,
                    "user_context_id": None,
                    "partition_key": None,
                    "private_browsing_id": None,
                },
            }
        )
    return observations
