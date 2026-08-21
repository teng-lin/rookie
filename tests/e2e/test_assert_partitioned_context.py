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


def cookie(name: str, value: str, context: dict) -> dict:
    return {
        "cookie": {
            "domain": (
                "top.rookie-a.test" if name == "rookie_top" else "third.rookie-b.test"
            ),
            "path": "/",
            "secure": True,
            "expires": 4_102_444_800,
            "name": name,
            "value": value,
            "http_only": True,
            "same_site": 0,
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

    def header(self, context: dict) -> str:
        top = context.get("top_level_site")
        if top is None:
            raise FakeError("incomplete_send_context")
        if "top.rookie-a.test" in top:
            values = ["rookie_chips=partitioned"]
            if any(record["cookie"]["name"] == "rookie_dfpi" for record in self.records):
                values.append("rookie_dfpi=partitioned-by-context")
            return "; ".join(values)
        return ""


class PartitionContextAssertionTests(unittest.TestCase):
    common = {
        "top_origin": "https://top.rookie-a.test:8766",
        "other_top_origin": "https://other.rookie-c.test:8766",
        "third_origin": "https://third.rookie-b.test:8766",
        "expected_source_port": 8766,
    }

    def test_valid_chromium_context_and_headers(self) -> None:
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top", {}),
                cookie(
                    "rookie_chips",
                    "partitioned",
                    {
                        "top_frame_site_key": "https://rookie-a.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
            ]
        )
        result = ASSERT.validate_context_snapshot(
            snapshot, engine="chromium", **self.common
        )
        self.assertEqual(result["headers"]["other_top_level_site"], "")
        self.assertEqual(len(result["detailed"]), 2)

    def test_valid_firefox_dfpi_context_and_headers(self) -> None:
        attributes = "^partitionKey=%28https%2Crookie-a.test%29"
        partition = "(https,rookie-a.test)"
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top", {"origin_attributes": ""}),
                cookie(
                    "rookie_chips",
                    "partitioned",
                    {
                        "origin_attributes": attributes,
                        "partition_key": partition,
                    },
                ),
                cookie(
                    "rookie_dfpi",
                    "partitioned-by-context",
                    {
                        "origin_attributes": attributes,
                        "partition_key": partition,
                    },
                ),
            ]
        )
        result = ASSERT.validate_context_snapshot(
            snapshot, engine="firefox", **self.common
        )
        self.assertIn("rookie_dfpi", result["headers"]["matching"])

    def test_wrong_top_level_partition_is_rejected(self) -> None:
        snapshot = FakeSnapshot(
            [
                cookie("rookie_top", "top", {}),
                cookie(
                    "rookie_chips",
                    "partitioned",
                    {
                        "top_frame_site_key": "https://wrong.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
            ]
        )
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "partition key"):
            ASSERT.validate_context_snapshot(snapshot, engine="chromium", **self.common)

    def test_cross_site_leak_is_rejected(self) -> None:
        class LeakySnapshot(FakeSnapshot):
            def header(self, context: dict) -> str:
                if context.get("top_level_site") is None:
                    raise FakeError("incomplete_send_context")
                return "rookie_chips=partitioned"

        snapshot = LeakySnapshot(
            [
                cookie("rookie_top", "top", {}),
                cookie(
                    "rookie_chips",
                    "partitioned",
                    {
                        "top_frame_site_key": "https://rookie-a.test",
                        "has_cross_site_ancestor": True,
                        "source_scheme": 2,
                        "source_port": 8766,
                        "is_persistent": True,
                    },
                ),
            ]
        )
        with self.assertRaisesRegex(ASSERT.ContextAssertionError, "different top-level"):
            ASSERT.validate_context_snapshot(snapshot, engine="chromium", **self.common)


if __name__ == "__main__":
    unittest.main()
