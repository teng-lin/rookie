#!/usr/bin/env python3
"""Assert browser-produced partition context and send-time isolation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Protocol

from cookie_manifest import ManifestError, load_manifest, verify_records


class ContextAssertionError(RuntimeError):
    """The detailed snapshot did not preserve browser isolation semantics."""


class Snapshot(Protocol):
    def detailed_cookies(self) -> list[dict[str, Any]]: ...

    def header(self, context: dict[str, Any]) -> str: ...


def normalized(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        records,
        key=lambda record: (
            record["cookie"]["domain"],
            record["cookie"]["path"],
            record["cookie"]["name"],
            json.dumps(record.get("context", {}), sort_keys=True),
        ),
    )


def context_value(context: dict[str, Any], snake: str, camel: str) -> Any:
    return context.get(snake, context.get(camel))


def header_tokens(header: str) -> list[str]:
    return sorted(token.strip() for token in header.split(";") if token.strip())


def schemeful_site(origin: str) -> str:
    """Return the controlled test origin's browser-persisted schemeful site."""

    from urllib.parse import urlparse

    parsed = urlparse(origin)
    host = parsed.hostname or ""
    labels = host.split(".")
    if len(labels) != 3 or labels[0] not in {"top", "other"}:
        raise ContextAssertionError(f"unexpected controlled top-level origin {origin!r}")
    return f"{parsed.scheme}://{'.'.join(labels[1:])}"


def validate_context_snapshot(
    snapshot: Snapshot,
    *,
    engine: str,
    top_origin: str,
    other_top_origin: str,
    third_origin: str,
    expected_source_port: int,
    raw_manifest: Path | None = None,
) -> dict[str, Any]:
    detailed = [
        record
        for record in snapshot.detailed_cookies()
        if record.get("cookie", {}).get("name", "").startswith("rookie_")
    ]
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in detailed:
        by_name.setdefault(record["cookie"]["name"], []).append(record)

    expected_counts = {"rookie_top": 2, "rookie_chips": 3}
    if engine == "firefox":
        expected_counts["rookie_dfpi"] = 2
    actual_counts = {name: len(records) for name, records in by_name.items()}
    if actual_counts != expected_counts:
        raise ContextAssertionError(
            f"context corpus mismatch: expected {expected_counts}, got {actual_counts}"
        )
    manifest = load_manifest(raw_manifest) if raw_manifest is not None else None
    if manifest is not None:
        verify_records(
            manifest,
            "detailed",
            detailed,
            surface=f"Python {engine} raw context",
        )

    for required in ("rookie_top", "rookie_chips"):
        expected = expected_counts[required]
        if len(by_name.get(required, [])) != expected:
            raise ContextAssertionError(
                f"expected exactly {expected} colliding {required} identities, "
                f"got {len(by_name.get(required, []))}"
            )

    top_contexts = [record.get("context", {}) for record in by_name["rookie_top"]]
    if engine == "chromium":
        if any(
            context_value(context, "top_frame_site_key", "topFrameSiteKey")
            not in (None, "")
            for context in top_contexts
        ):
            raise ContextAssertionError("a first-party top cookie became partitioned")
        unpartitioned = [
            record
            for record in by_name["rookie_chips"]
            if context_value(
                record.get("context", {}), "top_frame_site_key", "topFrameSiteKey"
            )
            in (None, "")
        ]
        if (
            len(unpartitioned) != 1
            or unpartitioned[0]["cookie"]["value"] != "unpartitioned"
        ):
            raise ContextAssertionError(
                "Chromium lost the unpartitioned cookie sharing the CHIPS flat identity"
            )
        keyed: dict[str, dict[str, Any]] = {}
        for record in by_name["rookie_chips"]:
            chips_context = record.get("context", {})
            key = context_value(chips_context, "top_frame_site_key", "topFrameSiteKey")
            if key in (None, ""):
                continue
            label = next(
                (
                    candidate
                    for candidate in ("a", "c")
                    if f"rookie-{candidate}.test" in str(key)
                ),
                None,
            )
            if label is None or label in keyed:
                raise ContextAssertionError(
                    f"unexpected Chromium partition keys: {key!r}"
                )
            keyed[label] = record
            if (
                context_value(
                    chips_context, "has_cross_site_ancestor", "hasCrossSiteAncestor"
                )
                is not True
            ):
                raise ContextAssertionError(
                    "CHIPS row lost its cross-site ancestor bit"
                )
            if (
                context_value(chips_context, "source_port", "sourcePort")
                != expected_source_port
            ):
                raise ContextAssertionError(
                    f"CHIPS source port was {context_value(chips_context, 'source_port', 'sourcePort')!r}"
                )
            if context_value(chips_context, "source_scheme", "sourceScheme") != 2:
                raise ContextAssertionError("CHIPS HTTPS source scheme was not 2")
            if (
                context_value(chips_context, "is_persistent", "isPersistent")
                is not True
            ):
                raise ContextAssertionError("CHIPS persistence bit was not true")
        for label, record in keyed.items():
            if record["cookie"]["value"] != f"partition-{label}":
                raise ContextAssertionError(
                    f"Chromium partition {label} carried {record['cookie']['value']!r}"
                )
    else:
        if len(by_name.get("rookie_dfpi", [])) != 2:
            raise ContextAssertionError(
                f"expected two Firefox dFPI rows, got {len(by_name.get('rookie_dfpi', []))}"
            )
        chips_unpartitioned = [
            record
            for record in by_name["rookie_chips"]
            if context_value(record.get("context", {}), "partition_key", "partitionKey")
            in (None, "")
        ]
        if (
            len(chips_unpartitioned) != 1
            or chips_unpartitioned[0]["cookie"]["value"] != "unpartitioned"
        ):
            raise ContextAssertionError(
                "Firefox lost the unpartitioned cookie sharing the partitioned flat identity"
            )
        for name in ("rookie_chips", "rookie_dfpi"):
            labels: set[str] = set()
            for record in by_name[name]:
                context = record.get("context", {})
                origin_attributes = context_value(
                    context, "origin_attributes", "originAttributes"
                )
                partition_key = context_value(context, "partition_key", "partitionKey")
                if name == "rookie_chips" and partition_key in (None, ""):
                    continue
                label = next(
                    (
                        candidate
                        for candidate in ("a", "c")
                        if f"rookie-{candidate}.test" in str(partition_key)
                    ),
                    None,
                )
                if label is None or label in labels:
                    raise ContextAssertionError(
                        f"{name} has unexpected parsed partition key {partition_key!r}"
                    )
                labels.add(label)
                if (
                    not isinstance(origin_attributes, str)
                    or "partitionKey=" not in origin_attributes
                ):
                    raise ContextAssertionError(
                        f"{name} lacks complete partitioned originAttributes"
                    )
                if context_value(context, "user_context_id", "userContextId") not in (
                    None,
                    0,
                ):
                    raise ContextAssertionError(
                        f"{name} unexpectedly entered a container"
                    )
                if context_value(
                    context, "private_browsing_id", "privateBrowsingId"
                ) not in (None, 0):
                    raise ContextAssertionError(
                        f"{name} unexpectedly entered private browsing"
                    )
                expected_value = (
                    f"partition-{label}" if name == "rookie_chips" else f"dfpi-{label}"
                )
                if record["cookie"]["value"] != expected_value:
                    raise ContextAssertionError(
                        f"{name} partition {label} carried {record['cookie']['value']!r}"
                    )

    matching_context = {
        "url": f"{third_origin}/echo",
        "top_level_site": schemeful_site(top_origin),
        "resource": "subresource",
        "method": "safe",
    }
    other_context = {
        **matching_context,
        "top_level_site": schemeful_site(other_top_origin),
    }
    matching_header = snapshot.header(matching_context)
    other_header = snapshot.header(other_context)
    expected_matching = [
        "rookie_chips=partition-a",
        "rookie_chips=unpartitioned",
    ]
    expected_other = [
        "rookie_chips=partition-c",
        "rookie_chips=unpartitioned",
    ]
    if engine == "firefox":
        expected_matching.append("rookie_dfpi=dfpi-a")
        expected_other.append("rookie_dfpi=dfpi-c")
    if manifest is not None:
        expected_matching = manifest["expected_headers"]["matching"]
        expected_other = manifest["expected_headers"]["other_top_level_site"]
    if header_tokens(matching_header) != sorted(expected_matching):
        raise ContextAssertionError(
            f"matching header set mismatch: expected {sorted(expected_matching)!r}, "
            f"got {header_tokens(matching_header)!r}"
        )
    if header_tokens(other_header) != sorted(expected_other):
        raise ContextAssertionError(
            f"other header set mismatch: expected {sorted(expected_other)!r}, "
            f"got {header_tokens(other_header)!r}"
        )

    try:
        snapshot.header(
            {
                "url": f"{third_origin}/echo",
                "resource": "subresource",
                "method": "safe",
            }
        )
    except Exception as error:  # public bindings expose a typed extension error
        code = getattr(error, "code", None)
        if code != "incomplete_send_context" and "incomplete_send_context" not in str(
            error
        ):
            raise ContextAssertionError(
                f"missing selector failed with the wrong error: {error!r}"
            ) from error
    else:
        raise ContextAssertionError(
            "partitioned snapshot accepted an incomplete context"
        )

    return {
        "engine": engine,
        "detailed": normalized(detailed),
        "headers": {
            "matching": matching_header,
            "other_top_level_site": other_header,
            "missing_selector": "incomplete_send_context",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--browser-id", default="chromium")
    parser.add_argument("--top-origin", required=True)
    parser.add_argument("--other-top-origin", required=True)
    parser.add_argument("--third-origin", required=True)
    parser.add_argument("--source-port", type=int, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        import rookie_cookies

        if args.engine == "chromium":
            snapshot = rookie_cookies.from_path(
                str(args.database), browser_id=args.browser_id
            )
        else:
            snapshot = rookie_cookies.from_path(str(args.database))
        result = validate_context_snapshot(
            snapshot,
            engine=args.engine,
            top_origin=args.top_origin,
            other_top_origin=args.other_top_origin,
            third_origin=args.third_origin,
            expected_source_port=args.source_port,
            raw_manifest=(
                Path(os.environ["ROOKIE_E2E_CONTEXT_MANIFEST"])
                if os.environ.get("ROOKIE_E2E_CONTEXT_MANIFEST")
                else None
            ),
        )
        encoded = (
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        )
        if args.output is None:
            print(encoded, end="")
        else:
            args.output.write_text(encoded, encoding="utf-8")
    except (ContextAssertionError, ManifestError, OSError, ValueError) as error:
        print(f"partition context assertion failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
