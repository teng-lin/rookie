"""Unit tests for partition-context assertions without a local browser."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


def load_module(name: str, filename: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ASSERT = load_module("assert_partitioned_context", "assert_partitioned_context.py")
# Reuse the module the assertion code itself imported: loading a second copy
# would give this test a different ManifestError class from the one raised.
ManifestError = ASSERT.ManifestError


def ancestor_corpus() -> list[dict]:
    return [
        cookie("rookie_top", "top-a", CHROMIUM_UNPARTITIONED),
        cookie("rookie_top", "top-c", CHROMIUM_UNPARTITIONED),
        cookie("rookie_chips", "unpartitioned", CHROMIUM_UNPARTITIONED),
        *CHROMIUM_ANCESTOR_ROWS,
    ]


def manifest_for(records: list[dict]) -> dict:
    """A minimal manifest carrying the send views the assertions read.

    The expected sets are written out by hand rather than derived, so a
    regression in the assertion code fails this test instead of two
    derivations quietly agreeing with each other.
    """

    nested = "https://nested.rookie-a.test:8766/set-ancestor"
    top = "https://top.rookie-a.test:8766/chain-top"
    base = {"resource": "subresource", "method": "safe"}
    ancestors = {
        record["cookie"]["value"]: record
        for record in records
        if record["cookie"]["name"] == "rookie_ancestor"
    }
    views = [
        {
            "name": "nested_same_site",
            "context": {
                "url": nested,
                "top_level_site": "https://rookie-a.test",
                "ancestor_chain": "same_site",
                **base,
            },
            "expected": [ancestors["ancestor-same_site"]],
            "header_tokens": ["rookie_ancestor=ancestor-same_site"],
            "expected_omitted_min": {"not_applicable": 3, "partition": 1},
        },
        {
            "name": "nested_cross_site",
            "context": {
                "url": nested,
                "top_level_site": "https://rookie-a.test",
                "ancestor_chain": "cross_site",
                **base,
            },
            "expected": [ancestors["ancestor-cross_site"]],
            "header_tokens": ["rookie_ancestor=ancestor-cross_site"],
            "expected_omitted_min": {"not_applicable": 3, "partition": 1},
        },
        {
            "name": "top_cross_site",
            "context": {
                "url": top,
                "top_level_site": "https://rookie-a.test",
                "ancestor_chain": "cross_site",
                **base,
            },
            "expected": [],
            "header_tokens": [],
            "expected_omitted_min": {"same_site": 1},
        },
    ]
    return {
        "schema_version": 1,
        "tiers": ["partition_context"],
        "identities": {
            "filtered_flat": ["domain", "path", "name"],
            "unfiltered_flat": ["domain", "path", "name"],
            "detailed": [
                "cookie.domain",
                "cookie.path",
                "cookie.name",
                "context.top_frame_site_key",
                "context.has_cross_site_ancestor",
                "context.source_scheme",
                "context.source_port",
                "context.is_persistent",
                "context.origin_attributes",
                "context.user_context_id",
                "context.partition_key",
                "context.private_browsing_id",
            ],
        },
        "expected": {
            "filtered_flat": [],
            "unfiltered_flat": [],
            "detailed": records,
        },
        "expected_send_views": views,
    }


def domain_for(name: str, value: str) -> str:
    if name == "rookie_top":
        return "other.rookie-c.test" if value == "top-c" else "top.rookie-a.test"
    if name == "rookie_ancestor":
        return "nested.rookie-a.test"
    return "third.rookie-b.test"


def cookie(name: str, value: str, context: dict) -> dict:
    return {
        "cookie": {
            "domain": domain_for(name, value),
            "path": "/",
            "secure": True,
            "expires": 4_102_444_800,
            "name": name,
            "value": value,
            "http_only": True,
            # The first-party page cookie is Lax, as the server sets it; every
            # third-party and partitioned row is SameSite=None.
            "same_site": 1 if name == "rookie_top" else 0,
        },
        "context": context,
    }


class FakeError(RuntimeError):
    code = "incomplete_send_context"


class FakeSnapshot:
    def __init__(self, records: list[dict]) -> None:
        self.records = records

    def detailed_cookies(self) -> list[dict]:
        return self.records

    def send_view(self, context: dict) -> dict:
        """A minimal stand-in for the real selection.

        Deliberately not a second implementation of the matching rules: it
        keeps rows whose host matches, drops the ancestor row that names the
        other chain, and drops a Lax row once the chain is cross-site. That is
        exactly enough to drive the assertion code under test.
        """

        host = context["url"].split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
        chain = context.get("ancestor_chain", "same_site")
        selected: list[dict] = []
        omitted = {
            "expired": 0,
            "not_applicable": 0,
            "same_site": 0,
            "partition": 0,
            "ancestor_chain_unknown": 0,
            "unparsable_partition_key": 0,
            "origin": 0,
        }
        for record in self.records:
            entry = record["cookie"]
            if entry["domain"] != host:
                omitted["not_applicable"] += 1
            elif entry["name"] == "rookie_ancestor" and entry[
                "value"
            ] != f"ancestor-{chain}":
                omitted["partition"] += 1
            elif entry["same_site"] >= 1 and chain == "cross_site":
                omitted["same_site"] += 1
            else:
                selected.append(record)
        return {
            "cookies": selected,
            "header": "; ".join(
                f"{record['cookie']['name']}={record['cookie']['value']}"
                for record in selected
            ),
            "omitted": omitted,
        }

    def header(self, context: dict) -> str:
        top = context.get("top_level_site")
        if top is None:
            raise FakeError("incomplete_send_context")
        if "rookie-a.test" in top:
            values = ["rookie_chips=partition-a", "rookie_chips=unpartitioned"]
            if any(
                record["cookie"]["name"] == "rookie_dfpi" for record in self.records
            ):
                values.append("rookie_dfpi=dfpi-a")
            return "; ".join(values)
        values = ["rookie_chips=partition-c", "rookie_chips=unpartitioned"]
        if any(record["cookie"]["name"] == "rookie_dfpi" for record in self.records):
            values.append("rookie_dfpi=dfpi-c")
        return "; ".join(values)


def chromium_context(**overrides: object) -> dict:
    """A complete Chromium CookieContext; the manifest verifier requires all nine."""

    context = {
        "top_frame_site_key": None,
        "has_cross_site_ancestor": None,
        "source_scheme": 2,
        "source_port": 8766,
        "is_persistent": True,
        "origin_attributes": None,
        "user_context_id": None,
        "partition_key": None,
        "private_browsing_id": None,
    }
    context.update(overrides)
    return context


CHROMIUM_UNPARTITIONED = chromium_context()
# The three views the stub manifest below declares. The real table lives in
# partition_context_inventory.json and is checked against the real seven-view
# manifest in test_partition_context_oracle.py.
STUB_FLOORS = {
    "nested_same_site": {
        "exact_values_by_name": {"rookie_ancestor": ["ancestor-same_site"]}
    },
    "nested_cross_site": {
        "exact_values_by_name": {"rookie_ancestor": ["ancestor-cross_site"]}
    },
    "top_cross_site": {"exact_values_by_name": {"rookie_top": []}},
}
FIREFOX_ANCESTOR_ROWS = [
    cookie(
        "rookie_ancestor",
        "ancestor-same_site",
        {"partition_key": None, "origin_attributes": ""},
    ),
    cookie(
        "rookie_ancestor",
        "ancestor-cross_site",
        {
            "partition_key": "(https,rookie-a.test,f)",
            "origin_attributes": "^partitionKey=%28https%2Crookie-a.test%2Cf%29",
        },
    ),
]
CHROMIUM_ANCESTOR_ROWS = [
    cookie(
        "rookie_ancestor",
        "ancestor-same_site",
        chromium_context(
            top_frame_site_key="https://rookie-a.test",
            has_cross_site_ancestor=False,
        ),
    ),
    cookie(
        "rookie_ancestor",
        "ancestor-cross_site",
        chromium_context(
            top_frame_site_key="https://rookie-a.test",
            has_cross_site_ancestor=True,
        ),
    ),
]


class PartitionContextAssertionTests(unittest.TestCase):
    common = {
        "top_origin": "https://top.rookie-a.test:8766",
        "other_top_origin": "https://other.rookie-c.test:8766",
        "third_origin": "https://third.rookie-b.test:8766",
        "expected_source_port": 8766,
    }

    def test_inventory_is_the_single_expected_row_table(self) -> None:
        chromium = ASSERT.row_inventory("chromium")
        firefox = ASSERT.row_inventory("firefox")
        self.assertEqual(chromium["raw_row_total"], 7)
        self.assertEqual(firefox["raw_row_total"], 9)
        self.assertEqual(chromium["raw_rows_by_name"]["rookie_ancestor"], 2)
        self.assertEqual(firefox["raw_rows_by_name"]["rookie_ancestor"], 2)
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "no webkit entry"):
            ASSERT.row_inventory("webkit")

    def test_ancestor_rows_must_stay_distinct(self) -> None:
        ASSERT.validate_ancestor_rows(CHROMIUM_ANCESTOR_ROWS, engine="chromium")
        collapsed = [CHROMIUM_ANCESTOR_ROWS[0], CHROMIUM_ANCESTOR_ROWS[0]]
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "distinct values"):
            ASSERT.validate_ancestor_rows(collapsed, engine="chromium")

    def test_ancestor_rows_must_carry_the_bit_that_separates_them(self) -> None:
        swapped = [
            {
                **CHROMIUM_ANCESTOR_ROWS[0],
                "context": {
                    **CHROMIUM_ANCESTOR_ROWS[0]["context"],
                    "has_cross_site_ancestor": True,
                },
            },
            CHROMIUM_ANCESTOR_ROWS[1],
        ]
        with self.assertRaisesRegex(
            ASSERT.ContextAssertionError, "has_cross_site_ancestor"
        ):
            ASSERT.validate_ancestor_rows(swapped, engine="chromium")

    def test_firefox_ancestor_rows_are_read_from_the_partition_tuple(self) -> None:
        rows = [
            cookie(
                "rookie_ancestor",
                "ancestor-same_site",
                {"partition_key": None, "origin_attributes": ""},
            ),
            cookie(
                "rookie_ancestor",
                "ancestor-cross_site",
                {
                    "partition_key": "(https,rookie-a.test,f)",
                    "origin_attributes": "^partitionKey=%28https%2Crookie-a.test%2Cf%29",
                },
            ),
        ]
        ASSERT.validate_ancestor_rows(rows, engine="firefox")
        rows[1]["context"]["partition_key"] = "(https,rookie-a.test)"
        with self.assertRaisesRegex(
            ASSERT.ContextAssertionError, "foreign-ancestor partitionKey"
        ):
            ASSERT.validate_ancestor_rows(rows, engine="firefox")

    def test_send_view_sets_are_compared_against_the_manifest(self) -> None:
        records = ancestor_corpus()
        views = ASSERT.validate_send_views(
            FakeSnapshot(records),
            engine="chromium",
            manifest=manifest_for(records),
            floors=STUB_FLOORS,
        )
        self.assertEqual(
            views["nested_same_site"], ["rookie_ancestor=ancestor-same_site"]
        )
        self.assertEqual(
            views["nested_cross_site"], ["rookie_ancestor=ancestor-cross_site"]
        )
        self.assertEqual(views["top_cross_site"], [])

    def test_send_view_mismatch_is_rejected(self) -> None:
        records = ancestor_corpus()
        manifest = manifest_for(records)
        # Claim the cross-site chain selects the same-site row: a library that
        # ignored the ancestor bit would produce exactly this.
        for view in manifest["expected_send_views"]:
            if view["name"] == "nested_cross_site":
                view["expected"] = [CHROMIUM_ANCESTOR_ROWS[0]]
                view["header_tokens"] = ["rookie_ancestor=ancestor-same_site"]
        with self.assertRaises(ManifestError):
            ASSERT.validate_send_views(
                FakeSnapshot(records),
                engine="chromium",
                manifest=manifest,
                floors=STUB_FLOORS,
            )

    def test_a_floor_catches_a_view_that_went_quietly_empty(self) -> None:
        # The oracle and the library read the same rows, so a shared misreading
        # would agree on an empty set. The floor is the assertion that cannot.
        records = ancestor_corpus()
        manifest = manifest_for(records)
        for view in manifest["expected_send_views"]:
            if view["name"] == "nested_cross_site":
                view["expected"] = []
                view["header_tokens"] = []

        class EmptySnapshot(FakeSnapshot):
            def send_view(self, context: dict) -> dict:
                if context.get("ancestor_chain") == "cross_site" and "nested" in str(
                    context["url"]
                ):
                    # Everything else about the answer still looks healthy: the
                    # header matches, and the omission counters clear their
                    # floors. Only the floor on the values notices.
                    view = super().send_view(context)
                    return {"cookies": [], "header": "", "omitted": view["omitted"]}
                return super().send_view(context)

        with self.assertRaisesRegex(
            ASSERT.ContextAssertionError, "rookie_ancestor values"
        ):
            ASSERT.validate_send_views(
                EmptySnapshot(records),
                engine="chromium",
                manifest=manifest,
                floors=STUB_FLOORS,
            )

    def test_a_floor_catches_a_missing_required_token(self) -> None:
        records = ancestor_corpus()
        floors = {
            **STUB_FLOORS,
            "top_cross_site": {"at_least": ["rookie_top=top-a"]},
        }
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "did not select"):
            ASSERT.validate_send_views(
                FakeSnapshot(records),
                engine="chromium",
                manifest=manifest_for(records),
                floors=floors,
            )

    def test_a_floor_for_a_view_the_manifest_never_ran_is_rejected(self) -> None:
        records = ancestor_corpus()
        floors = {**STUB_FLOORS, "matching": {"at_least": ["rookie_chips=x"]}}
        with self.assertRaisesRegex(
            ASSERT.ContextAssertionError, "the manifest never ran"
        ):
            ASSERT.validate_send_views(
                FakeSnapshot(records),
                engine="chromium",
                manifest=manifest_for(records),
                floors=floors,
            )

    def test_a_cross_site_view_that_keeps_a_lax_row_is_rejected(self) -> None:
        records = ancestor_corpus()
        manifest = manifest_for(records)

        class LaxLeakingSnapshot(FakeSnapshot):
            def send_view(self, context: dict) -> dict:
                view = super().send_view(context)
                if context.get("ancestor_chain") != "cross_site":
                    return view
                leaked = [
                    record
                    for record in self.records
                    if record["cookie"]["name"] == "rookie_top"
                    and record["cookie"]["value"] == "top-a"
                ]
                view["cookies"] = view["cookies"] + leaked
                view["omitted"]["same_site"] = 0
                return view

        with self.assertRaises(ManifestError):
            ASSERT.validate_send_views(
                LaxLeakingSnapshot(records),
                engine="chromium",
                manifest=manifest,
                floors=STUB_FLOORS,
            )

    def test_valid_chromium_context_and_headers(self) -> None:
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top-a", {}),
                cookie("rookie_top", "top-c", {}),
                cookie("rookie_chips", "unpartitioned", {}),
                cookie(
                    "rookie_chips",
                    "partition-a",
                    {
                        "top_frame_site_key": "https://rookie-a.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                cookie(
                    "rookie_chips",
                    "partition-c",
                    {
                        "top_frame_site_key": "https://rookie-c.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                *CHROMIUM_ANCESTOR_ROWS,
            ]
        )
        result = ASSERT.validate_context_snapshot(
            snapshot, engine="chromium", **self.common
        )
        self.assertIn("partition-c", result["headers"]["other_top_level_site"])
        self.assertEqual(len(result["detailed"]), 7)

    def test_valid_firefox_dfpi_context_and_headers(self) -> None:
        attributes_a = "^partitionKey=%28https%2Crookie-a.test%29"
        attributes_c = "^partitionKey=%28https%2Crookie-c.test%29"
        partition_a = "(https,rookie-a.test)"
        partition_c = "(https,rookie-c.test)"
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top-a", {"origin_attributes": ""}),
                cookie("rookie_top", "top-c", {"origin_attributes": ""}),
                cookie(
                    "rookie_chips",
                    "unpartitioned",
                    {"origin_attributes": "", "partition_key": None},
                ),
                cookie(
                    "rookie_chips",
                    "partition-a",
                    {
                        "origin_attributes": attributes_a,
                        "partition_key": partition_a,
                    },
                ),
                cookie(
                    "rookie_chips",
                    "partition-c",
                    {
                        "origin_attributes": attributes_c,
                        "partition_key": partition_c,
                    },
                ),
                cookie(
                    "rookie_dfpi",
                    "dfpi-a",
                    {
                        "origin_attributes": attributes_a,
                        "partition_key": partition_a,
                    },
                ),
                cookie(
                    "rookie_dfpi",
                    "dfpi-c",
                    {
                        "origin_attributes": attributes_c,
                        "partition_key": partition_c,
                    },
                ),
                *FIREFOX_ANCESTOR_ROWS,
            ]
        )
        result = ASSERT.validate_context_snapshot(
            snapshot, engine="firefox", **self.common
        )
        self.assertIn("rookie_dfpi", result["headers"]["matching"])

    def test_wrong_top_level_partition_is_rejected(self) -> None:
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top-a", {}),
                cookie("rookie_top", "top-c", {}),
                cookie("rookie_chips", "unpartitioned", {}),
                cookie(
                    "rookie_chips",
                    "partition-a",
                    {
                        "top_frame_site_key": "https://wrong.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                cookie(
                    "rookie_chips",
                    "partition-c",
                    {
                        "top_frame_site_key": "https://rookie-c.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                *CHROMIUM_ANCESTOR_ROWS,
            ]
        )
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "partition key"):
            ASSERT.validate_context_snapshot(snapshot, engine="chromium", **self.common)

    def test_cross_site_leak_is_rejected(self) -> None:
        class LeakySnapshot(FakeSnapshot):
            def header(self, context: dict) -> str:
                if context.get("top_level_site") is None:
                    raise FakeError("incomplete_send_context")
                return "rookie_chips=partition-a; rookie_chips=partition-c"

        snapshot = LeakySnapshot(
            [
                cookie("rookie_top", "top-a", {}),
                cookie("rookie_top", "top-c", {}),
                cookie("rookie_chips", "unpartitioned", {}),
                cookie(
                    "rookie_chips",
                    "partition-a",
                    {
                        "top_frame_site_key": "https://rookie-a.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                cookie(
                    "rookie_chips",
                    "partition-c",
                    {
                        "top_frame_site_key": "https://rookie-c.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
                *CHROMIUM_ANCESTOR_ROWS,
            ]
        )
        with self.assertRaisesRegex(
            ASSERT.ContextAssertionError, "header set mismatch"
        ):
            ASSERT.validate_context_snapshot(snapshot, engine="chromium", **self.common)


if __name__ == "__main__":
    unittest.main()
