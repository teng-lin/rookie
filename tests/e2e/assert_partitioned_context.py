#!/usr/bin/env python3
"""Assert browser-produced partition context and send-time isolation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Protocol

from cookie_manifest import (
    ManifestError,
    load_manifest,
    send_view_entry,
    send_view_manifest,
    send_view_names,
    verify_records,
)


INVENTORY_PATH = Path(__file__).with_name("partition_context_inventory.json")


class ContextAssertionError(RuntimeError):
    """The detailed snapshot did not preserve browser isolation semantics."""


class Snapshot(Protocol):
    def detailed_cookies(self) -> list[dict[str, Any]]: ...

    def header(self, context: dict[str, Any]) -> str: ...

    def send_view(self, context: dict[str, Any]) -> dict[str, Any]: ...


def row_inventory(engine: str) -> dict[str, Any]:
    """Return the one expected-row table every partition-context actor reads.

    The raw-store oracle, all four public-surface assertions, and the browser
    seeder read these counts from this single file, so a corpus change cannot
    land in some of them and be forgotten in the rest.
    """

    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContextAssertionError(
            f"cannot load {INVENTORY_PATH.name}: {error}"
        ) from error
    if inventory.get("schema_version") != 1:
        raise ContextAssertionError(
            f"unsupported partition inventory schema "
            f"{inventory.get('schema_version')!r}"
        )
    entry = inventory.get("engines", {}).get(engine)
    if entry is None:
        raise ContextAssertionError(f"{INVENTORY_PATH.name} has no {engine} entry")
    if sum(entry["raw_rows_by_name"].values()) != entry["raw_row_total"]:
        raise ContextAssertionError(
            f"{engine} inventory total disagrees with its per-name counts: {entry!r}"
        )
    return entry


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
    nested_origin: str | None = None,
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

    expected_counts = dict(row_inventory(engine)["raw_rows_by_name"])
    actual_counts = {name: len(records) for name, records in by_name.items()}
    if actual_counts != expected_counts:
        raise ContextAssertionError(
            f"context corpus mismatch: expected {expected_counts}, got {actual_counts}"
        )
    manifest = load_manifest(raw_manifest) if raw_manifest is not None else None
    if manifest is not None and nested_origin is not None:
        # The manifest carries the send contexts, so this is the one place the
        # runner's idea of the nested origin and the oracle's can be compared.
        nested = send_view_entry(manifest, "nested_derived")["context"]["url"]
        if not str(nested).startswith(f"{nested_origin}/"):
            raise ContextAssertionError(
                f"manifest nested context {nested!r} is not on {nested_origin!r}"
            )
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

    validate_ancestor_rows(by_name.get("rookie_ancestor", []), engine=engine)

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

    expected_missing = (
        manifest.get("expected_missing_selector") if manifest is not None else None
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
        if expected_missing is not None:
            # The tokens are the contract, not just the code: a caller branches
            # on `required` to decide which selector to ask its own caller for.
            required = list(getattr(error, "required", None) or [])
            if code != expected_missing["code"] or required != list(
                expected_missing["required"]
            ):
                raise ContextAssertionError(
                    f"missing selector named {code!r}/{required!r}, expected "
                    f"{expected_missing['code']!r}/{expected_missing['required']!r}"
                ) from error
    else:
        raise ContextAssertionError(
            "partitioned snapshot accepted an incomplete context"
        )

    send_views = (
        validate_send_views(snapshot, engine=engine, manifest=manifest)
        if manifest is not None
        else {}
    )

    return {
        "engine": engine,
        "detailed": normalized(detailed),
        "headers": {
            "matching": matching_header,
            "other_top_level_site": other_header,
            "missing_selector": "incomplete_send_context",
        },
        "send_views": send_views,
    }


def validate_ancestor_rows(records: list[dict[str, Any]], *, engine: str) -> None:
    """Require the two A -> A / A -> B -> A rows to survive as distinct rows.

    They share a name, host, and path by construction. If the library folds
    them together, or drops the field that separates them, the collision is
    invisible in every flat projection -- which is exactly the failure this
    lane exists to catch.
    """

    if not records:
        return
    values = sorted(record["cookie"]["value"] for record in records)
    if values != ["ancestor-cross_site", "ancestor-same_site"]:
        raise ContextAssertionError(
            f"the two ancestor-chain rows did not survive as distinct values: {values}"
        )
    for record in records:
        context = record.get("context", {})
        cross = record["cookie"]["value"] == "ancestor-cross_site"
        if engine == "chromium":
            bit = context_value(
                context, "has_cross_site_ancestor", "hasCrossSiteAncestor"
            )
            if bit is not cross:
                raise ContextAssertionError(
                    f"{record['cookie']['value']} carried "
                    f"has_cross_site_ancestor={bit!r}"
                )
            continue
        key = str(
            context_value(context, "partition_key", "partitionKey") or ""
        )
        if cross and not key.endswith(",f)"):
            raise ContextAssertionError(
                f"the A -> B -> A row lost its foreign-ancestor partitionKey: {key!r}"
            )
        if not cross and key.endswith(",f)"):
            raise ContextAssertionError(
                f"the same-site row gained a foreign-ancestor partitionKey: {key!r}"
            )


def omission_count(omitted: dict[str, Any], reason: str) -> int:
    """Read one omission counter from either spelling a binding may use."""

    camel = "".join(
        part.capitalize() if index else part
        for index, part in enumerate(reason.split("_"))
    )
    value = omitted.get(reason, omitted.get(camel))
    if not isinstance(value, int) or isinstance(value, bool):
        raise ContextAssertionError(
            f"send view omission {reason!r} was {value!r}, expected an integer"
        )
    return value


def validate_send_views(
    snapshot: Snapshot,
    *,
    engine: str,
    manifest: dict[str, Any],
    floors: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    """Compare every context's selected set against the raw-store oracle.

    Each expected set was derived from the browser's own SQLite rows, so this
    is a comparison between the library and the browser, not between the
    library and itself. `floors` defaults to the inventory's table for this
    engine and exists as a seam for tests driving a stub manifest.
    """

    cross = send_view_entry(manifest, "top_cross_site")
    if cross["expected_omitted_min"].get("same_site", 0) < 1:
        raise ContextAssertionError(
            "the explicit cross-site context must have a SameSite=Lax row to omit; "
            f"its oracle omits {cross['expected_omitted_min']!r}"
        )
    if cross["expected"]:
        raise ContextAssertionError(
            "declaring a same-site request cross-site must withhold its Lax rows, "
            f"but the oracle still selects {len(cross['expected'])}"
        )

    if floors is None:
        floors = row_inventory(engine).get("send_view_floors", {})
    selected_tokens: dict[str, list[str]] = {}
    for name in send_view_names(manifest):
        entry = send_view_entry(manifest, name)
        view = snapshot.send_view(dict(entry["context"]))
        records = [
            record
            for record in view["cookies"]
            if record.get("cookie", {}).get("name", "").startswith("rookie_")
        ]
        verify_records(
            send_view_manifest(manifest, name),
            "detailed",
            records,
            surface=f"{engine} send view {name}",
        )
        tokens = header_tokens(view["header"])
        if tokens != sorted(entry["header_tokens"]):
            raise ContextAssertionError(
                f"send view {name} rendered {tokens!r}, expected "
                f"{sorted(entry['header_tokens'])!r}"
            )
        for reason, minimum in entry["expected_omitted_min"].items():
            actual = omission_count(view["omitted"], reason)
            if actual < minimum:
                raise ContextAssertionError(
                    f"send view {name} counted {actual} {reason} omissions, "
                    f"expected at least {minimum}"
                )
        apply_send_view_floors(name, floors.get(name), records, tokens)
        selected_tokens[name] = tokens
    unchecked = sorted(set(floors) - set(selected_tokens))
    if unchecked:
        raise ContextAssertionError(
            f"{engine} declares floors for send views the manifest never ran: "
            f"{unchecked}"
        )
    return selected_tokens


def apply_send_view_floors(
    name: str,
    floors: dict[str, Any] | None,
    records: list[dict[str, Any]],
    tokens: list[str],
) -> None:
    """Hold one live send view to its hand-written floor.

    The oracle and the library read the same stored rows, so a shared
    misreading would make them agree on an empty set and leave every partition
    claim vacuously true. These floors are written out by hand, from what the
    browser was asked to store, and cannot go quiet.
    """

    if floors is None:
        return
    missing = sorted(set(floors.get("at_least", [])) - set(tokens))
    if missing:
        raise ContextAssertionError(
            f"send view {name} did not select the required {missing}; "
            f"it selected {tokens}"
        )
    for cookie_name, expected in floors.get("exact_values_by_name", {}).items():
        actual = sorted(
            record["cookie"]["value"]
            for record in records
            if record["cookie"]["name"] == cookie_name
        )
        if actual != sorted(expected):
            raise ContextAssertionError(
                f"send view {name} selected {cookie_name} values {actual}, "
                f"expected exactly {sorted(expected)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--browser-id", default="chromium")
    parser.add_argument("--top-origin", required=True)
    parser.add_argument("--other-top-origin", required=True)
    parser.add_argument("--third-origin", required=True)
    parser.add_argument("--nested-origin", required=True)
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
            nested_origin=args.nested_origin,
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
