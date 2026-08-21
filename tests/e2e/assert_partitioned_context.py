#!/usr/bin/env python3
"""Assert browser-produced partition context and send-time isolation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Protocol


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


def validate_context_snapshot(
    snapshot: Snapshot,
    *,
    engine: str,
    top_origin: str,
    other_top_origin: str,
    third_origin: str,
    expected_source_port: int,
) -> dict[str, Any]:
    detailed = [
        record
        for record in snapshot.detailed_cookies()
        if record.get("cookie", {}).get("name", "").startswith("rookie_")
    ]
    by_name: dict[str, list[dict[str, Any]]] = {}
    for record in detailed:
        by_name.setdefault(record["cookie"]["name"], []).append(record)

    for required in ("rookie_top", "rookie_chips"):
        if len(by_name.get(required, [])) != 1:
            raise ContextAssertionError(
                f"expected exactly one {required}, got {len(by_name.get(required, []))}"
            )

    top_context = by_name["rookie_top"][0].get("context", {})
    if engine == "chromium":
        if context_value(top_context, "top_frame_site_key", "topFrameSiteKey") not in (
            None,
            "",
        ):
            raise ContextAssertionError("first-party top cookie became partitioned")
        chips_context = by_name["rookie_chips"][0].get("context", {})
        key = context_value(
            chips_context, "top_frame_site_key", "topFrameSiteKey"
        )
        if not isinstance(key, str) or "rookie-a.test" not in key:
            raise ContextAssertionError(f"unexpected Chromium partition key {key!r}")
        if context_value(
            chips_context, "has_cross_site_ancestor", "hasCrossSiteAncestor"
        ) is not True:
            raise ContextAssertionError("CHIPS row lost its cross-site ancestor bit")
        if context_value(chips_context, "source_port", "sourcePort") != expected_source_port:
            raise ContextAssertionError(
                f"CHIPS source port was {context_value(chips_context, 'source_port', 'sourcePort')!r}"
            )
        if context_value(chips_context, "source_scheme", "sourceScheme") is None:
            raise ContextAssertionError("CHIPS source scheme was not observed")
        if context_value(chips_context, "is_persistent", "isPersistent") is not True:
            raise ContextAssertionError("CHIPS persistence bit was not true")
    else:
        if len(by_name.get("rookie_dfpi", [])) != 1:
            raise ContextAssertionError(
                f"expected one Firefox dFPI row, got {len(by_name.get('rookie_dfpi', []))}"
            )
        for name in ("rookie_chips", "rookie_dfpi"):
            context = by_name[name][0].get("context", {})
            origin_attributes = context_value(
                context, "origin_attributes", "originAttributes"
            )
            partition_key = context_value(context, "partition_key", "partitionKey")
            if not isinstance(origin_attributes, str) or "partitionKey=" not in origin_attributes:
                raise ContextAssertionError(
                    f"{name} lacks complete partitioned originAttributes"
                )
            if not isinstance(partition_key, str) or "rookie-a.test" not in partition_key:
                raise ContextAssertionError(
                    f"{name} has unexpected parsed partition key {partition_key!r}"
                )
            if context_value(context, "user_context_id", "userContextId") not in (
                None,
                0,
            ):
                raise ContextAssertionError(f"{name} unexpectedly entered a container")
            if context_value(
                context, "private_browsing_id", "privateBrowsingId"
            ) not in (None, 0):
                raise ContextAssertionError(f"{name} unexpectedly entered private browsing")

    matching_context = {
        "url": f"{third_origin}/echo",
        "top_level_site": top_origin,
        "resource": "subresource",
        "method": "safe",
    }
    other_context = {**matching_context, "top_level_site": other_top_origin}
    matching_header = snapshot.header(matching_context)
    other_header = snapshot.header(other_context)
    if "rookie_chips=partitioned" not in matching_header:
        raise ContextAssertionError(
            f"matching send context omitted CHIPS cookie: {matching_header!r}"
        )
    if "rookie_chips=partitioned" in other_header:
        raise ContextAssertionError(
            f"different top-level site received CHIPS cookie: {other_header!r}"
        )
    if engine == "firefox":
        if "rookie_dfpi=partitioned-by-context" not in matching_header:
            raise ContextAssertionError(
                f"matching Firefox context omitted dFPI cookie: {matching_header!r}"
            )
        if "rookie_dfpi=partitioned-by-context" in other_header:
            raise ContextAssertionError(
                f"different top-level site received dFPI cookie: {other_header!r}"
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
        raise ContextAssertionError("partitioned snapshot accepted an incomplete context")

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
        )
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output is None:
            print(encoded, end="")
        else:
            args.output.write_text(encoded, encoding="utf-8")
    except (ContextAssertionError, OSError, ValueError) as error:
        print(f"partition context assertion failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
