"""The Python binding driven against the shared isolation collision corpus.

`tests/isolation_corpus/corpus.json` is the one description of what each
engine's stored isolation identity means, and every language binds to the same
core selection. This module is Python's side of that: it builds the corpus
stores with the committed generator, then asserts that `send_view` answers each
case with exactly the listed cookies in the listed order, the listed header,
and the listed omission counts -- and that `as_jar` reaches the listed verdict
for each store.

Three properties are checked that no single case can express on its own:

* `header(ctx)` equals `send_view(ctx)["header"]` for every case, including the
  error cases (both must raise the same code). Two ways to ask the same
  question must not answer differently.
* Every omission reason is present in `omitted` with a zero count when the
  corpus does not list it, so a consumer can index one without a guard.
* `as_jar(allow_isolation_loss=True)` equals `to_cookiejar(as_list())`
  cookie-for-cookie -- the opt-in changes whether the projection is produced,
  never what it contains.

The generator is imported by path rather than installed, the same way
`test_export_contract.py` reaches `export_contract`.
"""

from __future__ import annotations

import http.cookiejar
import sys
import tempfile
import unittest
from pathlib import Path

import rookie_cookies

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_DIR = _REPO_ROOT / "tests" / "isolation_corpus"
if str(_CORPUS_DIR) not in sys.path:
    sys.path.insert(0, str(_CORPUS_DIR))

import build_isolation_corpus  # noqa: E402  (path is set up immediately above)

# Every omission reason `SendOmissions::entries()` yields, in its declared
# order. A case lists only the non-zero ones; the rest must still be present
# and zero, which is what makes the serialized shape fixed across releases.
_OMISSION_CODES = (
    "expired",
    "not_applicable",
    "same_site",
    "partition",
    "ancestor_chain_unknown",
    "unparsable_partition_key",
    "origin",
)

# Corpus cases this binding deliberately does not assert, because the case
# itself cannot be satisfied by any implementation of ADR 0006 -- not because
# the binding disagrees with it. The corpus is owned elsewhere; these entries
# come out the moment the cases are fixed there, and `test_every_excluded_case
# _still_exists` fails if one is silently renamed away instead.
#
# Each value is the reason, kept here so a reader does not have to reconstruct
# the analysis from a bare id.
_UNSATISFIABLE_CASES = {
    "chromium_site_ipv4_exact_host_equality_required": (
        "The case's request URL, https://7.198.51.100.7/, has no parseable "
        "host: all five labels are numeric, so the WHATWG URL parser runs its "
        "IPv4 parser and rejects more than four parts. `url::Url::parse` "
        "implements that spec, so the context is rejected with `invalid_url` "
        "before any matching happens -- which ADR 0006 requires ('an "
        "unparseable ... is rejected rather than dropped'). The IP-literal "
        "exact-equality rule the case exists for is still covered by "
        "chromium_site_ipv6_exact_host_equality_required, which passes."
    ),
    "firefox_unknown_attr_partitioned_row_survives_raw_selector": (
        "The `firefox_unknown_partitioned` row this case expects is "
        "unreachable by any context in its store. Its partitionKey is "
        "(https,rookie-a.test) with no `,f`, and the row is a host-only "
        "Secure cookie on unknown.rookie-a.test -- a subdomain of the "
        "top-level site. So sites_match is always true, an explicit "
        "ancestor_chain=cross_site makes foreignByAncestorContext true (which "
        "demands a `,f` tuple), and ancestor_chain=same_site instead trips "
        "ADR 0006's 'a partitioned Firefox row never matches a first-party "
        "context' guard. The raw-selector property the case exists for -- an "
        "exact `origin_attributes` does not filter non-opaque rows -- is still "
        "covered by firefox_unknown_attr_exact_future_suffix, which selects a "
        "non-opaque row alongside the opaque one."
    ),
}


def _selected_values(view: dict) -> list[str]:
    """The corpus identifies each row by its value, which equals its id."""
    return [record["cookie"]["value"] for record in view["cookies"]]


def _jar_entries(jar: http.cookiejar.CookieJar) -> list[tuple]:
    return sorted(
        (
            cookie.domain,
            cookie.path,
            cookie.name,
            cookie.value,
            cookie.secure,
            cookie.expires,
        )
        for cookie in jar
    )


class IsolationCorpusTest(unittest.TestCase):
    """Builds every corpus store once, then drives the binding over it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._corpus = build_isolation_corpus.load_corpus()
        # ignore_cleanup_errors: the stores are SQLite files this process just
        # closed, and a stray handle on a slow filesystem must not turn a
        # passing suite red at teardown.
        cls._temp = tempfile.TemporaryDirectory(
            prefix="rookie-isolation-corpus-", ignore_cleanup_errors=True
        )
        cls._paths = build_isolation_corpus.build_all_stores(
            cls._corpus, Path(cls._temp.name)
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temp.cleanup()

    def _snapshot(self, store: str) -> rookie_cookies.ReadResult:
        # include_expired keeps the snapshot's inventory whole; send-time
        # expiry is applied by send_view regardless, and is what the corpus's
        # `expired` omission count measures.
        return rookie_cookies.from_path(str(self._paths[store]), include_expired=True)

    # -- cases ---------------------------------------------------------------

    def test_every_case_selects_exactly_what_the_corpus_lists(self) -> None:
        for case in self._corpus["cases"]:
            if case["id"] in _UNSATISFIABLE_CASES:
                continue
            with self.subTest(case=case["id"]):
                snapshot = self._snapshot(case["store"])
                context = dict(case["context"])
                expect = case["expect"]

                if "error" in expect:
                    with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                        snapshot.send_view(context)
                    self.assertEqual(raised.exception.code, expect["error"]["code"])
                    self.assertEqual(
                        list(raised.exception.required), expect["error"]["required"]
                    )
                    continue

                view = snapshot.send_view(context)
                # Order is part of the contract, not just membership.
                self.assertEqual(_selected_values(view), expect["selected"])
                self.assertEqual(view["header"], expect["header"])

                listed = expect.get("omitted", {})
                self.assertEqual(
                    set(view["omitted"]), set(_OMISSION_CODES),
                    "send_view must always yield every omission reason",
                )
                for code in _OMISSION_CODES:
                    with self.subTest(omission=code):
                        self.assertEqual(view["omitted"][code], listed.get(code, 0))

    def test_header_is_exactly_the_send_view_header_for_every_case(self) -> None:
        for case in self._corpus["cases"]:
            if case["id"] in _UNSATISFIABLE_CASES:
                continue
            with self.subTest(case=case["id"]):
                snapshot = self._snapshot(case["store"])
                context = dict(case["context"])
                if "error" in case["expect"]:
                    # The two entry points must also fail identically.
                    with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                        snapshot.header(context)
                    self.assertEqual(
                        raised.exception.code, case["expect"]["error"]["code"]
                    )
                    continue
                self.assertEqual(
                    snapshot.header(context), snapshot.send_view(context)["header"]
                )

    def test_send_view_accepts_the_same_context_as_keyword_arguments(self) -> None:
        """The mapping and keyword forms are one vocabulary, not two."""
        for case in self._corpus["cases"]:
            if case["id"] in _UNSATISFIABLE_CASES or "error" in case["expect"]:
                continue
            with self.subTest(case=case["id"]):
                snapshot = self._snapshot(case["store"])
                context = dict(case["context"])
                url = context.pop("url")
                self.assertEqual(
                    snapshot.send_view(url, **context)["header"],
                    case["expect"]["header"],
                )

    def test_every_excluded_case_still_exists(self) -> None:
        """An exclusion must name a real case, so a fix cannot go unnoticed."""
        ids = {case["id"] for case in self._corpus["cases"]}
        for excluded in _UNSATISFIABLE_CASES:
            with self.subTest(case=excluded):
                self.assertIn(
                    excluded,
                    ids,
                    "this exclusion names no corpus case -- delete it, and "
                    "stop skipping a case that no longer exists",
                )

    # -- per-store jar verdicts ----------------------------------------------

    def test_each_store_reaches_its_listed_jar_verdict(self) -> None:
        for store, description in self._corpus["stores"].items():
            expect = description["jar"]["expect"]
            with self.subTest(store=store):
                snapshot = self._snapshot(store)
                if expect == "ok":
                    self.assertIsInstance(snapshot.as_jar(), http.cookiejar.CookieJar)
                    continue
                with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                    snapshot.as_jar()
                self.assertEqual(raised.exception.code, expect["error"]["code"])
                self.assertEqual(
                    list(raised.exception.required), expect["error"]["required"]
                )

    def test_the_opt_in_jar_matches_the_inventory_projection_cookie_for_cookie(
        self,
    ) -> None:
        """Opting in changes whether the jar is produced, never its contents."""
        for store in self._corpus["stores"]:
            with self.subTest(store=store):
                snapshot = self._snapshot(store)
                opted_in = snapshot.as_jar(allow_isolation_loss=True)
                inventory = rookie_cookies.to_cookiejar(snapshot.as_list())
                self.assertEqual(_jar_entries(opted_in), _jar_entries(inventory))
                self.assertEqual(
                    snapshot.compatibility_cookies(allow_isolation_loss=True),
                    snapshot.as_list(),
                )

    def test_a_plain_store_is_unaffected_by_the_opt_in(self) -> None:
        """The fail-closed default is invisible to an unisolated snapshot."""
        plain = [
            store
            for store, description in self._corpus["stores"].items()
            if description["jar"]["expect"] == "ok"
        ]
        self.assertTrue(plain, "the corpus must keep at least one plain store")
        for store in plain:
            with self.subTest(store=store):
                snapshot = self._snapshot(store)
                self.assertEqual(
                    _jar_entries(snapshot.as_jar()),
                    _jar_entries(snapshot.as_jar(allow_isolation_loss=True)),
                )
                self.assertEqual(
                    snapshot.compatibility_cookies(),
                    snapshot.compatibility_cookies(allow_isolation_loss=True),
                )

    def test_a_refusal_names_the_selectors_send_view_would_need(self) -> None:
        """`required` is one vocabulary, shared with incomplete_send_context."""
        for store, description in self._corpus["stores"].items():
            expect = description["jar"]["expect"]
            if expect == "ok":
                continue
            with self.subTest(store=store):
                snapshot = self._snapshot(store)
                with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                    snapshot.as_jar()
                required = list(raised.exception.required)
                self.assertTrue(required, "a refusal must say what to supply instead")
                # Naming the tokens is not decoration: a send_view call that
                # supplies none of them fails with the same list.
                row = description["rows"][0]
                url = f"https://{row.get('host_key') or row['host']}/"
                with self.assertRaises(rookie_cookies.RookieRequestError) as demanded:
                    snapshot.send_view(url, now=self._corpus["clock_epoch_seconds"])
                self.assertEqual(demanded.exception.code, "incomplete_send_context")
                self.assertEqual(list(demanded.exception.required), required)


if __name__ == "__main__":
    unittest.main()
