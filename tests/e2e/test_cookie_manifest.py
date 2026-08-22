"""Adversarial unit tests for the independent cookie exact-set verifier."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest


E2E_DIR = Path(__file__).parent
sys.path.insert(0, str(E2E_DIR))
from cookie_manifest import ManifestError, validate_manifest, verify_records  # noqa: E402


def flat(
    name: str = "rookie_ci",
    *,
    domain: str = "127.0.0.1",
    path: str = "/",
    value: str = "bar",
) -> dict:
    return {
        "domain": domain,
        "path": path,
        "secure": False,
        "expires": 4_102_444_800,
        "name": name,
        "value": value,
        "http_only": False,
        "same_site": 1,
    }


def context() -> dict:
    return {
        "top_frame_site_key": None,
        "has_cross_site_ancestor": False,
        "source_scheme": 1,
        "source_port": 8765,
        "is_persistent": True,
        "origin_attributes": None,
        "user_context_id": None,
        "partition_key": None,
        "private_browsing_id": None,
    }


def manifest() -> dict:
    one = flat()
    decoy = flat("rookie_decoy", domain="localhost", value="no")
    return {
        "schema_version": 1,
        "engine": "chromium",
        "tiers": ["portable_smoke"],
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
            "filtered_flat": [one],
            "unfiltered_flat": [one, decoy],
            "detailed": [
                {"cookie": one, "context": context()},
                {"cookie": decoy, "context": context()},
            ],
        },
    }


class CookieManifestVerifierTests(unittest.TestCase):
    def test_accepts_exact_sets_regardless_of_order(self) -> None:
        expected = manifest()
        actual = list(reversed(copy.deepcopy(expected["expected"]["unfiltered_flat"])))
        self.assertEqual(
            verify_records(expected, "unfiltered_flat", actual, surface="unit surface"),
            2,
        )

    def test_normalizes_node_camel_case_detailed_output(self) -> None:
        expected = manifest()
        record = copy.deepcopy(expected["expected"]["detailed"][0])
        record["cookie"]["httpOnly"] = record["cookie"].pop("http_only")
        record["cookie"]["sameSite"] = record["cookie"].pop("same_site")
        record["context"]["topFrameSiteKey"] = record["context"].pop(
            "top_frame_site_key"
        )
        record["context"]["hasCrossSiteAncestor"] = record["context"].pop(
            "has_cross_site_ancestor"
        )
        record["context"]["sourceScheme"] = record["context"].pop("source_scheme")
        record["context"]["sourcePort"] = record["context"].pop("source_port")
        record["context"]["isPersistent"] = record["context"].pop("is_persistent")
        record["context"]["originAttributes"] = record["context"].pop(
            "origin_attributes"
        )
        record["context"]["userContextId"] = record["context"].pop("user_context_id")
        record["context"]["partitionKey"] = record["context"].pop("partition_key")
        record["context"]["privateBrowsingId"] = record["context"].pop(
            "private_browsing_id"
        )
        expected["expected"]["detailed"] = expected["expected"]["detailed"][:1]
        self.assertEqual(
            verify_records(expected, "detailed", [record], surface="Node"), 1
        )

    def assert_mutation_fails(self, records: list[dict], pattern: str) -> None:
        with self.assertRaisesRegex(ManifestError, pattern):
            verify_records(
                manifest(), "filtered_flat", records, surface="mutated surface"
            )

    def test_extra_row_fails(self) -> None:
        self.assert_mutation_fails([flat(), flat("unexpected")], "excess identities")

    def test_duplicate_identity_fails(self) -> None:
        self.assert_mutation_fails([flat(), flat()], "duplicate identity")

    def test_missing_row_fails(self) -> None:
        self.assert_mutation_fails([], "missing identities")

    def test_wrong_domain_fails(self) -> None:
        self.assert_mutation_fails([flat(domain="other.test")], "missing identities")

    def test_wrong_attribute_fails(self) -> None:
        record = flat()
        record["http_only"] = True
        self.assert_mutation_fails([record], "mismatch for")

    def test_wrong_context_fails(self) -> None:
        expected = manifest()
        actual = copy.deepcopy(expected["expected"]["detailed"])
        actual[0]["context"]["partition_key"] = "(https,example.test)"
        with self.assertRaisesRegex(ManifestError, "missing identities"):
            verify_records(expected, "detailed", actual, surface="context mutation")

    def test_wrong_shape_fails_instead_of_ignoring_fields(self) -> None:
        record = flat()
        record["raw_value"] = "plaintext sentinel"
        self.assert_mutation_fails([record], "wrong shape.*excess")

    def test_controlled_origin_scope_allows_vendor_rows_but_not_target_excess(
        self,
    ) -> None:
        expected = manifest()
        expected["verification_scope"] = {
            "cookie_domains": ["127.0.0.1", "localhost"],
            "browser_owned_external_rows_observed": 24,
        }
        vendor = flat("yp", domain=".yandex.ru", value="browser-owned")
        actual = [*copy.deepcopy(expected["expected"]["unfiltered_flat"]), vendor]
        self.assertEqual(
            verify_records(expected, "unfiltered_flat", actual, surface="Yandex"), 2
        )
        actual.append(flat("unexpected_target"))
        with self.assertRaisesRegex(ManifestError, "excess identities"):
            verify_records(expected, "unfiltered_flat", actual, surface="Yandex")

    def test_real_corpus_declares_extensible_tiers_and_applicability(self) -> None:
        corpus = json.loads(
            (E2E_DIR / "cookie_corpus.json").read_text(encoding="utf-8")
        )
        self.assertEqual(corpus["schema_version"], 1)
        self.assertTrue({"portable_smoke", "deep", "stress"} <= set(corpus["tiers"]))
        scenario_ids = [scenario["id"] for scenario in corpus["scenarios"]]
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))
        for scenario in corpus["scenarios"]:
            self.assertTrue(scenario["tiers"])
            self.assertTrue(set(scenario["tiers"]) <= set(corpus["tiers"]))
            self.assertTrue(scenario["applicability"]["engines"])
            self.assertTrue(scenario["applicability"]["platforms"])
            self.assertEqual(
                set(scenario["expected"]["same_site"]),
                set(scenario["applicability"]["engines"]),
            )
        # The sample manifest also pins schema validation independently of a browser.
        validate_manifest(manifest())


if __name__ == "__main__":
    unittest.main()
