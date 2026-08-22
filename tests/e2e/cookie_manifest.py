#!/usr/bin/env python3
"""Cookie-corpus manifest loading, normalization, and exact-set verification.

The browser seeder writes the expected manifest. Extraction adapters supply
their own output to this module. The verifier deliberately has no dependency
on rookie-cookies, so the expected side cannot accidentally reuse production
projection logic.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


MANIFEST_FILENAME = "rookie-e2e-cookie-manifest.json"
FLAT_FIELDS = (
    "domain",
    "path",
    "secure",
    "expires",
    "name",
    "value",
    "http_only",
    "same_site",
)
CONTEXT_FIELDS = (
    "top_frame_site_key",
    "has_cross_site_ancestor",
    "source_scheme",
    "source_port",
    "is_persistent",
    "origin_attributes",
    "user_context_id",
    "partition_key",
    "private_browsing_id",
)
PROJECTIONS = ("filtered_flat", "unfiltered_flat", "detailed")


class ManifestError(AssertionError):
    """An exact-set contract violation with a surface-oriented message."""


def _snake_case(name: str) -> str:
    output: list[str] = []
    for char in name:
        if char.isupper():
            output.extend(("_", char.lower()))
        else:
            output.append(char)
    return "".join(output)


def _normalize_keys(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            _snake_case(str(key)): _normalize_keys(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_keys(item) for item in value]
    return value


def _require_exact_keys(
    record: Mapping[str, Any], fields: Sequence[str], label: str
) -> None:
    actual = set(record)
    expected = set(fields)
    missing = sorted(expected - actual)
    excess = sorted(actual - expected)
    if missing or excess:
        raise ManifestError(
            f"{label} has the wrong shape; missing={missing or '[]'}, "
            f"excess={excess or '[]'}"
        )


def normalize_flat(record: Any, *, label: str = "cookie") -> dict[str, Any]:
    record = _normalize_keys(record)
    if not isinstance(record, Mapping):
        raise ManifestError(f"{label} must be an object, got {type(record).__name__}")
    _require_exact_keys(record, FLAT_FIELDS, label)
    normalized = {field: record[field] for field in FLAT_FIELDS}
    if normalized["expires"] is not None:
        expires = normalized["expires"]
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            raise ManifestError(f"{label}.expires must be an integer or null")
        if int(expires) != expires:
            raise ManifestError(f"{label}.expires must be an integral Unix timestamp")
        normalized["expires"] = int(expires)
    for field in ("secure", "http_only"):
        if not isinstance(normalized[field], bool):
            raise ManifestError(f"{label}.{field} must be boolean")
    if isinstance(normalized["same_site"], bool) or not isinstance(
        normalized["same_site"], int
    ):
        raise ManifestError(f"{label}.same_site must be an integer")
    for field in ("domain", "path", "name", "value"):
        if not isinstance(normalized[field], str):
            raise ManifestError(f"{label}.{field} must be a string")
    return normalized


def normalize_detailed(record: Any, *, label: str = "record") -> dict[str, Any]:
    record = _normalize_keys(record)
    if not isinstance(record, Mapping):
        raise ManifestError(f"{label} must be an object, got {type(record).__name__}")
    _require_exact_keys(record, ("cookie", "context"), label)
    context = record["context"]
    if not isinstance(context, Mapping):
        raise ManifestError(f"{label}.context must be an object")
    _require_exact_keys(context, CONTEXT_FIELDS, f"{label}.context")
    return {
        "cookie": normalize_flat(record["cookie"], label=f"{label}.cookie"),
        "context": {field: context[field] for field in CONTEXT_FIELDS},
    }


def _path_value(record: Mapping[str, Any], dotted_path: str) -> Any:
    value: Any = record
    for component in dotted_path.split("."):
        if not isinstance(value, Mapping) or component not in value:
            raise ManifestError(f"identity field {dotted_path!r} is absent")
        value = value[component]
    return value


def _identity(
    record: Mapping[str, Any], identity_fields: Sequence[str]
) -> tuple[str, ...]:
    # JSON encoding makes None/bool/number/string ordering deterministic and
    # avoids Python's refusal to compare unlike scalar types.
    return tuple(
        json.dumps(_path_value(record, field), sort_keys=True, ensure_ascii=False)
        for field in identity_fields
    )


def _canonical(record: Mapping[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _cookie_domain(record: Mapping[str, Any], projection: str) -> str:
    cookie = record["cookie"] if projection == "detailed" else record
    return str(cookie["domain"]).removeprefix(".").lower()


def _validate_no_duplicate_identities(
    records: Sequence[Mapping[str, Any]],
    identity_fields: Sequence[str],
    label: str,
) -> None:
    seen: dict[tuple[str, ...], int] = {}
    for index, record in enumerate(records):
        identity = _identity(record, identity_fields)
        if identity in seen:
            raise ManifestError(
                f"{label} contains duplicate identity {identity} at indexes "
                f"{seen[identity]} and {index}"
            )
        seen[identity] = index


def load_manifest(path: Path | str) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ManifestError(
            f"cannot load cookie manifest {manifest_path}: {error}"
        ) from error
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, Mapping):
        raise ManifestError("cookie manifest must be an object")
    if manifest.get("schema_version") != 1:
        raise ManifestError(
            f"unsupported cookie manifest schema_version {manifest.get('schema_version')!r}"
        )
    tiers = manifest.get("tiers")
    if (
        not isinstance(tiers, list)
        or not tiers
        or not all(isinstance(item, str) for item in tiers)
    ):
        raise ManifestError("cookie manifest tiers must be a non-empty string array")
    identities = manifest.get("identities")
    expected = manifest.get("expected")
    if not isinstance(identities, Mapping) or not isinstance(expected, Mapping):
        raise ManifestError(
            "cookie manifest must contain identities and expected objects"
        )
    for projection in PROJECTIONS:
        fields = identities.get(projection)
        records = expected.get(projection)
        if (
            not isinstance(fields, list)
            or not fields
            or not all(isinstance(item, str) for item in fields)
        ):
            raise ManifestError(
                f"manifest identity {projection!r} must be a string array"
            )
        if not isinstance(records, list):
            raise ManifestError(f"manifest expected.{projection} must be an array")
        normalizer = normalize_detailed if projection == "detailed" else normalize_flat
        normalized = [
            normalizer(item, label=f"expected.{projection}[{index}]")
            for index, item in enumerate(records)
        ]
        _validate_no_duplicate_identities(normalized, fields, f"expected.{projection}")
    scope = manifest.get("verification_scope")
    if scope is not None:
        if not isinstance(scope, Mapping):
            raise ManifestError("manifest verification_scope must be an object")
        domains = scope.get("cookie_domains")
        if (
            not isinstance(domains, list)
            or not domains
            or not all(isinstance(item, str) and item for item in domains)
        ):
            raise ManifestError(
                "manifest verification_scope.cookie_domains must be a non-empty string array"
            )
        normalized_domains = {item.removeprefix(".").lower() for item in domains}
        for projection in PROJECTIONS:
            normalizer = (
                normalize_detailed if projection == "detailed" else normalize_flat
            )
            for index, item in enumerate(expected[projection]):
                record = normalizer(item, label=f"expected.{projection}[{index}]")
                if _cookie_domain(record, projection) not in normalized_domains:
                    raise ManifestError(
                        f"expected.{projection}[{index}] falls outside verification_scope"
                    )


def verify_records(
    manifest: Mapping[str, Any],
    projection: str,
    actual: Iterable[Any],
    *,
    surface: str,
) -> int:
    """Assert exact sorted-set equality and return the verified row count."""
    validate_manifest(manifest)
    if projection not in PROJECTIONS:
        raise ManifestError(
            f"unknown projection {projection!r}; expected one of {PROJECTIONS}"
        )
    if not isinstance(actual, list):
        actual = list(actual)
    normalizer = normalize_detailed if projection == "detailed" else normalize_flat
    actual_normalized = [
        normalizer(item, label=f"{surface}[{index}]")
        for index, item in enumerate(actual)
    ]
    scope = manifest.get("verification_scope")
    if scope is not None:
        domains = {item.removeprefix(".").lower() for item in scope["cookie_domains"]}
        actual_normalized = [
            record
            for record in actual_normalized
            if _cookie_domain(record, projection) in domains
        ]
    expected_normalized = [
        normalizer(item, label=f"expected.{projection}[{index}]")
        for index, item in enumerate(manifest["expected"][projection])
    ]
    identity_fields = manifest["identities"][projection]
    _validate_no_duplicate_identities(actual_normalized, identity_fields, surface)
    _validate_no_duplicate_identities(
        expected_normalized, identity_fields, f"expected.{projection}"
    )

    actual_by_id = {
        _identity(record, identity_fields): record for record in actual_normalized
    }
    expected_by_id = {
        _identity(record, identity_fields): record for record in expected_normalized
    }
    actual_ids = set(actual_by_id)
    expected_ids = set(expected_by_id)
    missing = sorted(expected_ids - actual_ids)
    excess = sorted(actual_ids - expected_ids)
    mismatched = sorted(
        identity
        for identity in actual_ids & expected_ids
        if _canonical(actual_by_id[identity]) != _canonical(expected_by_id[identity])
    )
    if missing or excess or mismatched:
        details: list[str] = [
            f"{surface} does not exactly match {projection}: "
            f"expected {len(expected_normalized)} rows, got {len(actual_normalized)}"
        ]
        if missing:
            details.append(f"missing identities: {missing}")
        if excess:
            details.append(f"excess identities: {excess}")
        for identity in mismatched:
            details.append(
                f"mismatch for {identity}: expected={_canonical(expected_by_id[identity])} "
                f"actual={_canonical(actual_by_id[identity])}"
            )
        raise ManifestError("; ".join(details))
    return len(actual_normalized)


def find_manifest(
    profile_or_db: Path | str | None,
    *,
    expected_name: str | None = None,
) -> Path | None:
    """Find a seeder manifest without opting special one-cookie canaries in.

    An explicit ROOKIE_E2E_COOKIE_MANIFEST always wins. Inferred manifests are
    used only for the ordinary rookie_ci corpus. The WAL/App-Bound canary sets
    ROOKIE_E2E_COOKIE_NAME=rookie_wal and intentionally keeps its focused
    legacy assertion.
    """
    explicit = os.environ.get("ROOKIE_E2E_COOKIE_MANIFEST")
    if explicit:
        return Path(explicit)
    selected_name = expected_name or os.environ.get(
        "ROOKIE_E2E_COOKIE_NAME", "rookie_ci"
    )
    if selected_name != "rookie_ci" or profile_or_db is None:
        return None
    start = Path(profile_or_db)
    if start.is_file():
        start = start.parent
    for candidate_root in (start, *start.parents):
        candidate = candidate_root / MANIFEST_FILENAME
        if candidate.is_file():
            return candidate
    return None
