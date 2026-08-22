"""Small state-transition contract used by the active-writer E2E lane.

PR 1's exact corpus is the broader semantic oracle. This helper is deliberately
scoped to PR 3: every public surface must observe one value replacement, one
addition, and one deletion at each active-writer checkpoint. The coordinator
also enables exact-state mode so unrelated or duplicate rows cannot hide.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from typing import Any


REQUIRED_ENV = "ROOKIE_E2E_REQUIRED_COOKIES_JSON"
FORBIDDEN_ENV = "ROOKIE_E2E_FORBIDDEN_COOKIES_JSON"
EXACT_ENV = "ROOKIE_E2E_EXACT_COOKIE_STATE"


def state_from_environment(
    default_name: str, default_value: str
) -> tuple[dict[str, str], list[str]]:
    raw_required = os.environ.get(REQUIRED_ENV)
    required: Any = (
        json.loads(raw_required)
        if raw_required is not None
        else {default_name: default_value}
    )
    raw_forbidden = os.environ.get(FORBIDDEN_ENV, "[]")
    forbidden: Any = json.loads(raw_forbidden)
    if not isinstance(required, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in required.items()
    ):
        raise ValueError(f"{REQUIRED_ENV} must be a JSON object of strings")
    if not isinstance(forbidden, list) or not all(
        isinstance(name, str) for name in forbidden
    ):
        raise ValueError(f"{FORBIDDEN_ENV} must be a JSON array of strings")
    overlap = set(required).intersection(forbidden)
    if overlap:
        raise ValueError(
            f"required and forbidden cookie names overlap: {sorted(overlap)}"
        )
    return required, forbidden


def assert_cookie_state(
    cookies: Sequence[Mapping[str, Any]],
    required: Mapping[str, str],
    forbidden: Sequence[str],
    *,
    surface: str,
) -> None:
    for name, value in required.items():
        matches = [cookie for cookie in cookies if cookie.get("name") == name]
        if len(matches) != 1:
            raise AssertionError(
                f"{surface}: expected exactly one {name!r}, got {len(matches)}"
            )
        actual = matches[0].get("value")
        if actual != value:
            raise AssertionError(
                f"{surface}: {name!r} expected value {value!r}, got {actual!r}"
            )
    for name in forbidden:
        matches = [cookie for cookie in cookies if cookie.get("name") == name]
        if matches:
            raise AssertionError(
                f"{surface}: forbidden/deleted cookie {name!r} remained ({len(matches)} row(s))"
            )
    if os.environ.get(EXACT_ENV) == "1":
        actual_names = [cookie.get("name") for cookie in cookies]
        if len(cookies) != len(required) or set(actual_names) != set(required):
            raise AssertionError(
                f"{surface}: exact active-writer set mismatch; "
                f"expected names {sorted(required)}, got {sorted(map(str, actual_names))}"
            )
