"""Tests for the raw-store oracle behind the partition-context send views.

The oracle reads a browser's own SQLite rows and derives, without the library
under test, which rows each send context should select. These tests drive it
against hand-built stores so its rules can be checked on any machine, with no
browser and no CI sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from assert_partitioned_context import row_inventory
from run_active_writer_e2e import ActiveWriterError
from run_partition_context_e2e import (
    _firefox_isolation_reason,
    _omission_reason,
    write_raw_context_manifest,
)


PORT = 8766
ORIGINS = {
    "top": f"https://top.rookie-a.test:{PORT}",
    "other_top": f"https://other.rookie-c.test:{PORT}",
    "third": f"https://third.rookie-b.test:{PORT}",
    "nested": f"https://nested.rookie-a.test:{PORT}",
}
CHROMIUM_EPOCH_OFFSET = 11_644_473_600_000_000
EXPIRES = 4_102_444_800


def chromium_store(path: Path, rows: list[dict[str, object]]) -> Path:
    database = path / "Cookies"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            create table cookies (
              host_key text,
              name text,
              path text,
              expires_utc integer,
              is_secure integer,
              is_httponly integer,
              samesite integer,
              top_frame_site_key text,
              has_cross_site_ancestor integer,
              source_scheme integer,
              source_port integer,
              is_persistent integer
            )
            """
        )
        connection.executemany(
            "insert into cookies values (:host_key, :name, :path, :expires_utc, "
            ":is_secure, :is_httponly, :samesite, :top_frame_site_key, "
            ":has_cross_site_ancestor, :source_scheme, :source_port, :is_persistent)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()
    return database


def chromium_row(
    name: str,
    host: str,
    *,
    same_site: int,
    top_frame_site_key: str | None = None,
    has_cross_site_ancestor: int | None = None,
) -> dict[str, object]:
    return {
        "host_key": host,
        "name": name,
        "path": "/",
        "expires_utc": EXPIRES * 1_000_000 + CHROMIUM_EPOCH_OFFSET,
        "is_secure": 1,
        "is_httponly": 1,
        "samesite": same_site,
        "top_frame_site_key": top_frame_site_key,
        "has_cross_site_ancestor": has_cross_site_ancestor,
        "source_scheme": 2,
        "source_port": PORT,
        "is_persistent": 1,
    }


CHROMIUM_ROWS = [
    chromium_row("rookie_top", "top.rookie-a.test", same_site=1),
    chromium_row("rookie_top", "other.rookie-c.test", same_site=1),
    chromium_row("rookie_chips", "third.rookie-b.test", same_site=0),
    chromium_row(
        "rookie_chips",
        "third.rookie-b.test",
        same_site=0,
        top_frame_site_key="https://rookie-a.test",
        has_cross_site_ancestor=1,
    ),
    chromium_row(
        "rookie_chips",
        "third.rookie-b.test",
        same_site=0,
        top_frame_site_key="https://rookie-c.test",
        has_cross_site_ancestor=1,
    ),
    chromium_row(
        "rookie_ancestor",
        "nested.rookie-a.test",
        same_site=0,
        top_frame_site_key="https://rookie-a.test",
        has_cross_site_ancestor=0,
    ),
    chromium_row(
        "rookie_ancestor",
        "nested.rookie-a.test",
        same_site=0,
        top_frame_site_key="https://rookie-a.test",
        has_cross_site_ancestor=1,
    ),
]


def firefox_store(path: Path, rows: list[dict[str, object]]) -> Path:
    database = path / "cookies.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute("pragma user_version = 16")
        connection.execute(
            """
            create table moz_cookies (
              name text,
              value text,
              host text,
              path text,
              expiry integer,
              isSecure integer,
              isHttpOnly integer,
              sameSite integer,
              originAttributes text
            )
            """
        )
        connection.executemany(
            "insert into moz_cookies values (:name, :value, :host, :path, :expiry, "
            ":isSecure, :isHttpOnly, :sameSite, :originAttributes)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()
    return database


def firefox_row(
    name: str,
    value: str,
    host: str,
    *,
    same_site: int,
    origin_attributes: str = "",
) -> dict[str, object]:
    return {
        "name": name,
        "value": value,
        "host": host,
        "path": "/",
        "expiry": EXPIRES * 1000,
        "isSecure": 1,
        "isHttpOnly": 1,
        "sameSite": same_site,
        "originAttributes": origin_attributes,
    }


PARTITION_A = "^partitionKey=%28https%2Crookie-a.test%29"
PARTITION_C = "^partitionKey=%28https%2Crookie-c.test%29"
PARTITION_A_FOREIGN = "^partitionKey=%28https%2Crookie-a.test%2Cf%29"


def firefox_rows(same_site_ancestor_attributes: str) -> list[dict[str, object]]:
    return [
        firefox_row("rookie_top", "top-a", "top.rookie-a.test", same_site=1),
        firefox_row("rookie_top", "top-c", "other.rookie-c.test", same_site=1),
        firefox_row(
            "rookie_chips", "unpartitioned", "third.rookie-b.test", same_site=0
        ),
        firefox_row(
            "rookie_chips",
            "partition-a",
            "third.rookie-b.test",
            same_site=0,
            origin_attributes=PARTITION_A,
        ),
        firefox_row(
            "rookie_chips",
            "partition-c",
            "third.rookie-b.test",
            same_site=0,
            origin_attributes=PARTITION_C,
        ),
        firefox_row(
            "rookie_dfpi",
            "dfpi-a",
            "third.rookie-b.test",
            same_site=0,
            origin_attributes=PARTITION_A,
        ),
        firefox_row(
            "rookie_dfpi",
            "dfpi-c",
            "third.rookie-b.test",
            same_site=0,
            origin_attributes=PARTITION_C,
        ),
        firefox_row(
            "rookie_ancestor",
            "ancestor-same_site",
            "nested.rookie-a.test",
            same_site=0,
            origin_attributes=same_site_ancestor_attributes,
        ),
        firefox_row(
            "rookie_ancestor",
            "ancestor-cross_site",
            "nested.rookie-a.test",
            same_site=0,
            origin_attributes=PARTITION_A_FOREIGN,
        ),
    ]


def build_manifest(
    engine: str, rows: list[dict[str, object]], root: Path
) -> dict[str, object]:
    builder = chromium_store if engine == "chromium" else firefox_store
    database = builder(root, rows)
    output = root / "manifest.json"
    write_raw_context_manifest(
        database,
        engine,
        output,
        origins=ORIGINS,
        browser_version=f"{engine}/test",
    )
    return json.loads(output.read_text(encoding="utf-8"))


def selected(manifest: dict[str, object], name: str) -> list[str]:
    view = next(
        entry for entry in manifest["expected_send_views"] if entry["name"] == name
    )
    return sorted(
        f"{record['cookie']['name']}={record['cookie']['value']}"
        for record in view["expected"]
    )


# What the two engines were actually observed to write: Chromium 151 stores
# both ancestor bits, and Firefox 153 partitions even the direct same-site
# iframe, so its same-site row carries the plain A key rather than no key. The
# inventory floors are written against these shapes.
OBSERVED_STORES = (
    ("chromium", CHROMIUM_ROWS),
    ("firefox", firefox_rows(PARTITION_A)),
)


class PartitionContextOracleTests(unittest.TestCase):
    def test_chromium_ancestor_bit_splits_two_otherwise_identical_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest("chromium", CHROMIUM_ROWS, Path(temporary))
        ancestors = [
            record
            for record in manifest["expected"]["detailed"]
            if record["cookie"]["name"] == "rookie_ancestor"
        ]
        self.assertEqual(
            sorted(record["cookie"]["value"] for record in ancestors),
            ["ancestor-cross_site", "ancestor-same_site"],
        )
        # The rows differ in nothing but the bit, so reconstructing the value
        # from the bit is itself the assertion that the bit survived.
        self.assertEqual(
            {
                record["cookie"]["value"]: record["context"]["has_cross_site_ancestor"]
                for record in ancestors
            },
            {"ancestor-same_site": False, "ancestor-cross_site": True},
        )

    def test_chromium_send_views_follow_the_resolved_ancestor_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest("chromium", CHROMIUM_ROWS, Path(temporary))
        self.assertEqual(
            selected(manifest, "matching"),
            ["rookie_chips=partition-a", "rookie_chips=unpartitioned"],
        )
        self.assertEqual(
            selected(manifest, "other_top_level_site"),
            ["rookie_chips=partition-c", "rookie_chips=unpartitioned"],
        )
        # The derived chain and the explicit same-site selector must agree.
        self.assertEqual(
            selected(manifest, "nested_derived"),
            ["rookie_ancestor=ancestor-same_site"],
        )
        self.assertEqual(
            selected(manifest, "nested_same_site"),
            selected(manifest, "nested_derived"),
        )
        self.assertEqual(
            selected(manifest, "nested_cross_site"),
            ["rookie_ancestor=ancestor-cross_site"],
        )
        self.assertEqual(selected(manifest, "top_first_party"), ["rookie_top=top-a"])

    def test_declaring_a_same_site_request_cross_site_withholds_lax_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest("chromium", CHROMIUM_ROWS, Path(temporary))
        view = next(
            entry
            for entry in manifest["expected_send_views"]
            if entry["name"] == "top_cross_site"
        )
        self.assertEqual(view["expected"], [])
        self.assertEqual(view["expected_omitted_min"]["same_site"], 1)

    def test_partitioned_row_demands_the_top_level_site_and_nothing_else(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest("chromium", CHROMIUM_ROWS, Path(temporary))
        self.assertEqual(
            manifest["expected_missing_selector"],
            {"code": "incomplete_send_context", "required": ["top_level_site"]},
        )

    def test_a_chromium_store_without_the_ancestor_column_fails_loudly(self) -> None:
        rows = [dict(row) for row in CHROMIUM_ROWS]
        for row in rows:
            if row["name"] == "rookie_ancestor":
                row["has_cross_site_ancestor"] = None
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                ActiveWriterError, "no usable has_cross_site_ancestor"
            ):
                build_manifest("chromium", rows, Path(temporary))

    def test_firefox_foreign_ancestor_tuple_is_required_never_skipped(self) -> None:
        rows = firefox_rows("")
        for row in rows:
            if row["value"] == "ancestor-cross_site":
                row["originAttributes"] = PARTITION_A
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                ActiveWriterError, r"firefox/test wrote no foreign-by-ancestor"
            ):
                build_manifest("firefox", rows, Path(temporary))

    def test_firefox_send_views_honour_the_foreign_ancestor_bit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest("firefox", firefox_rows(""), Path(temporary))
        self.assertEqual(
            selected(manifest, "matching"),
            [
                "rookie_chips=partition-a",
                "rookie_chips=unpartitioned",
                "rookie_dfpi=dfpi-a",
            ],
        )
        # The alternative shape: a Firefox that treated the direct same-site
        # iframe as first party would leave its row unpartitioned and reachable
        # from the first-party context. Firefox 153 does not, which is what the
        # inventory floor for `nested_derived` pins; a build that changed back
        # would fail that floor rather than pass unnoticed.
        self.assertEqual(
            selected(manifest, "nested_derived"),
            ["rookie_ancestor=ancestor-same_site"],
        )
        self.assertIn(
            "rookie_ancestor=ancestor-cross_site",
            selected(manifest, "nested_cross_site"),
        )

    def test_a_partitioned_firefox_same_site_row_never_joins_a_first_party_send(
        self,
    ) -> None:
        # The other shape Firefox could write: the same-site iframe partitioned
        # under the plain A key. A partition is not the default context, so the
        # first-party request must select nothing, and the cross-site request
        # must reject it for carrying no foreign-ancestor marker.
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_manifest(
                "firefox", firefox_rows(PARTITION_A), Path(temporary)
            )
        self.assertEqual(selected(manifest, "nested_derived"), [])
        self.assertEqual(
            selected(manifest, "nested_cross_site"),
            ["rookie_ancestor=ancestor-cross_site"],
        )

    def test_an_unreadable_firefox_key_is_unparsable_even_first_party(self) -> None:
        # `RequestIsolation::verdict` answers "opaque" before any field-by-field
        # gate, so an unreadable key is withheld as `unparsable_partition_key`
        # in every context -- including the first-party one, where the guard
        # below it would otherwise have claimed the row as `partition`.
        broken = {"partition_key": "(https,rookie-a.test", "origin_attributes": "^x"}
        first_party = {
            "url": f"https://rookie-a.test:{PORT}/",
            "top_level_site": "https://rookie-a.test",
        }
        self.assertEqual(
            _firefox_isolation_reason(
                broken,
                first_party,
                sites_match=True,
                resolved="same_site",
                same_site_context=True,
            ),
            "unparsable_partition_key",
        )
        self.assertEqual(
            _firefox_isolation_reason(
                broken,
                {**first_party, "url": f"https://third.rookie-b.test:{PORT}/"},
                sites_match=False,
                resolved="cross_site",
                same_site_context=False,
            ),
            "unparsable_partition_key",
        )

    def test_the_oracle_refuses_a_context_it_does_not_model(self) -> None:
        record = {
            "cookie": {
                "domain": "rookie-a.test",
                "path": "/",
                "secure": True,
                "expires": EXPIRES,
                "name": "rookie_x",
                "value": "x",
                "http_only": False,
                "same_site": 0,
            },
            "context": {"partition_key": None, "origin_attributes": ""},
        }
        with self.assertRaisesRegex(ActiveWriterError, "does not model"):
            _omission_reason(
                record,
                {
                    "url": "https://rookie-a.test/",
                    "top_level_site": "https://rookie-a.test",
                    "origin_attributes": "^futureAttr=1",
                },
                "firefox",
            )

    def test_every_floor_names_a_context_the_lane_actually_runs(self) -> None:
        # The floors are only a backstop if each one lands on a real view; a
        # renamed context would otherwise take its floor out of service.
        for engine, rows in OBSERVED_STORES:
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as temporary:
                manifest = build_manifest(engine, rows, Path(temporary))
                names = {view["name"] for view in manifest["expected_send_views"]}
                floors = row_inventory(engine)["send_view_floors"]
                self.assertEqual(set(floors), names, engine)
                for name, floor in floors.items():
                    self.assertTrue(
                        set(floor) <= {"at_least", "exact_values_by_name"}, name
                    )
                    self.assertTrue(floor, name)

    def test_the_declared_floors_hold_for_the_derived_sets(self) -> None:
        # The floors are hand-written from what the browser was asked to store.
        # They must agree with what the oracle derives, or one of the two is
        # wrong and the lane would be arguing with itself in CI.
        for engine, rows in OBSERVED_STORES:
            with self.subTest(engine=engine), tempfile.TemporaryDirectory() as temporary:
                manifest = build_manifest(engine, rows, Path(temporary))
                floors = row_inventory(engine)["send_view_floors"]
                for view in manifest["expected_send_views"]:
                    floor = floors[view["name"]]
                    tokens = selected(manifest, view["name"])
                    self.assertTrue(
                        set(floor.get("at_least", [])) <= set(tokens), view["name"]
                    )
                    for name, expected in floor.get(
                        "exact_values_by_name", {}
                    ).items():
                        actual = sorted(
                            record["cookie"]["value"]
                            for record in view["expected"]
                            if record["cookie"]["name"] == name
                        )
                        self.assertEqual(actual, sorted(expected), view["name"])

    def test_a_row_count_that_disagrees_with_the_inventory_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ActiveWriterError, "chromium/test"):
                build_manifest("chromium", CHROMIUM_ROWS[:-1], Path(temporary))


if __name__ == "__main__":
    unittest.main()
