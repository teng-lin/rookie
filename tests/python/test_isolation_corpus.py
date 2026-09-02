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
  error cases (both must raise the same code and the same `required`). Two
  ways to ask the same question must not answer differently.
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

# The stub reader lives beside the other contract tests; reusing it keeps one
# parser for "what does rookie_cookies.pyi declare", rather than a second
# regex here that could disagree with it.
from test_export_contract import _stub_typed_dict_keys  # noqa: E402

# Every omission reason `SendOmissions::entries()` yields, in its declared
# order. A case lists only the non-zero ones; the rest must still be present
# and zero, which is what makes the serialized shape fixed across releases.
#
# Spelled out rather than derived from the stub, because the *order* is part
# of the contract and a set cannot carry it.
# `test_the_omission_vocabulary_matches_the_stub` cross-asserts the membership
# against `rookie_cookies.pyi`, so the two cannot drift apart.
_OMISSION_CODES = (
    "expired",
    "not_applicable",
    "same_site",
    "partition",
    "ancestor_chain_unknown",
    "unparsable_partition_key",
    "origin",
)


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
        """Opens one store the way the corpus says it must be opened.

        `include_expired` defaults to false and is a per-store declaration,
        not a blanket convenience: read-time expiry decides whether a row
        reaches the snapshot at all, while send-time expiry drops it again
        regardless -- which is what the `expired` omission count measures. A
        store that declares the flag is making a statement about its own rows,
        so honouring it (rather than passing `True` everywhere) is what keeps
        this suite's counts the same ones the Rust and CLI consumers assert.
        """
        description = self._corpus["stores"][store]
        snapshot = rookie_cookies.from_path(
            str(self._paths[store]),
            include_expired=description.get("include_expired", False),
        )
        # A store whose flag is wrong loses rows silently, and every later
        # count would then be off by that much. Fail here instead.
        self.assertEqual(
            len(snapshot.detailed_cookies()),
            len(description["rows"]),
            f"store {store} lost rows between the corpus and the snapshot",
        )
        return snapshot

    # -- cases ---------------------------------------------------------------

    def test_every_case_selects_exactly_what_the_corpus_lists(self) -> None:
        for case in self._corpus["cases"]:
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
            with self.subTest(case=case["id"]):
                snapshot = self._snapshot(case["store"])
                context = dict(case["context"])
                if "error" in case["expect"]:
                    # The two entry points must also fail identically -- same
                    # code and the same tokens, not merely both raising.
                    with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                        snapshot.header(context)
                    self.assertEqual(
                        raised.exception.code, case["expect"]["error"]["code"]
                    )
                    self.assertEqual(
                        list(raised.exception.required),
                        case["expect"]["error"]["required"],
                    )
                    continue
                self.assertEqual(
                    snapshot.header(context), snapshot.send_view(context)["header"]
                )

    def test_send_view_accepts_the_same_context_as_keyword_arguments(self) -> None:
        """The mapping and keyword forms are one vocabulary, not two."""
        for case in self._corpus["cases"]:
            if "error" in case["expect"]:
                continue
            with self.subTest(case=case["id"]):
                snapshot = self._snapshot(case["store"])
                context = dict(case["context"])
                url = context.pop("url")
                self.assertEqual(
                    snapshot.send_view(url, **context)["header"],
                    case["expect"]["header"],
                )

    def _case(self, case_id: str) -> dict:
        for case in self._corpus["cases"]:
            if case["id"] == case_id:
                return case
        raise AssertionError(f"the corpus declares no case {case_id!r}")

    def test_an_explicit_selector_kwarg_overrides_the_same_mapping_key(self) -> None:
        """Precedence is observable through the selection, not just the build.

        The Rust unit tests compare the built `SendContext`; these two go
        through a real store, so a key wired into the merge but dropped before
        matching would still be caught. Each asserts both directions: the
        kwarg wins, and the mapping's own value would have produced something
        different -- otherwise "the kwarg won" proves nothing.
        """
        chain = self._case("chromium_ancestor_explicit_cross_site_a_to_b_to_a")
        snapshot = self._snapshot(chain["store"])
        wrong = dict(chain["context"], ancestor_chain="same_site")
        self.assertEqual(
            snapshot.send_view(wrong, ancestor_chain="cross_site")["header"],
            chain["expect"]["header"],
        )
        self.assertNotEqual(
            snapshot.send_view(wrong)["header"], chain["expect"]["header"]
        )

        suffix = self._case("firefox_unknown_attr_exact_future_suffix")
        snapshot = self._snapshot(suffix["store"])
        wrong = dict(suffix["context"], origin_attributes="")
        self.assertEqual(
            snapshot.send_view(wrong, origin_attributes="^futureAttr=1")["header"],
            suffix["expect"]["header"],
        )
        self.assertNotEqual(
            snapshot.send_view(wrong)["header"], suffix["expect"]["header"]
        )

    def test_a_malformed_selector_is_a_request_error_not_a_silent_default(
        self,
    ) -> None:
        """A typo in the caller's isolation intent must not be answered.

        An unrecognized `ancestor_chain` spelling falling back to the derived
        chain would answer a question the caller did not ask, and an unknown
        mapping key would let a misspelled selector be silently ignored.
        """
        snapshot = self._snapshot("chromium_isolated")
        probes = {
            "unknown ancestor_chain": lambda: snapshot.send_view(
                "https://nested.rookie-a.test/",
                top_level_site="https://rookie-a.test",
                ancestor_chain="samesite",
            ),
            "unknown mapping key": lambda: snapshot.send_view(
                {"url": "https://nested.rookie-a.test/", "ancestorChain": "same_site"}
            ),
        }
        for label, probe in probes.items():
            with self.subTest(probe=label):
                with self.assertRaises(rookie_cookies.RookieRequestError) as raised:
                    probe()
                self.assertEqual(raised.exception.kind, "request")
                # `code` is None for a fault raised on the binding's own side
                # of the boundary: these never reach a core `RequestError`, so
                # there is no typed code to report. This is the same shape the
                # pre-existing `resource` / `method` rejections have always
                # had, and it is pinned here so a later change to give them
                # codes is a deliberate one rather than a silent break for a
                # caller matching on `code is None`.
                self.assertIsNone(raised.exception.code)
                self.assertEqual(list(raised.exception.required), [])

    def test_the_corpus_this_suite_drives_has_not_collapsed(self) -> None:
        """A guard on every loop above, all of which are `for case in ...`.

        Each of those passes trivially over an empty list, so a corpus that
        failed to load, or one whose cases moved under a different key, would
        report a green suite having asserted nothing at all. The floors are
        deliberately loose -- this catches collapse, not growth.
        """
        cases = self._corpus["cases"]
        self.assertGreater(len(cases), 25, "the corpus case set collapsed")
        self.assertGreater(len(self._corpus["stores"]), 3, "the store set collapsed")
        self.assertEqual(
            len({case["id"] for case in cases}),
            len(cases),
            "two corpus cases share an id",
        )
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertIn(case["store"], self._corpus["stores"])

    def test_the_omission_vocabulary_matches_the_stub(self) -> None:
        """This module's ordered list and the stub's TypedDict are one set.

        The order lives here because a `TypedDict`'s keys do not carry it;
        the membership lives in the stub. Cross-asserting is what stops a
        reason added to one from being missed by the other.
        """
        self.assertEqual(
            set(_OMISSION_CODES), _stub_typed_dict_keys("SendOmissions")
        )
        self.assertEqual(
            len(_OMISSION_CODES),
            len(set(_OMISSION_CODES)),
            "an omission reason is listed twice",
        )

    # -- per-store jar verdicts ----------------------------------------------

    def test_each_store_reaches_its_listed_jar_verdict(self) -> None:
        for store, description in self._corpus["stores"].items():
            expect = description["jar"]["expect"]
            with self.subTest(store=store):
                snapshot = self._snapshot(store)
                if expect == "ok":
                    jar = snapshot.as_jar()
                    self.assertIsInstance(jar, http.cookiejar.CookieJar)
                    # A jar that quietly dropped rows would still be a jar.
                    self.assertEqual(len(list(jar)), len(snapshot))
                    self.assertEqual(
                        len(snapshot.compatibility_cookies()), len(snapshot)
                    )
                    continue
                # Both send-safe names refuse, with the same code and the same
                # tokens: `as_jar` is sugar over `compatibility_cookies`, and
                # a caller who avoids the jar shape must not thereby avoid the
                # policy.
                for name, probe in (
                    ("as_jar", snapshot.as_jar),
                    ("compatibility_cookies", snapshot.compatibility_cookies),
                ):
                    with self.subTest(projection=name):
                        with self.assertRaises(
                            rookie_cookies.RookieRequestError
                        ) as raised:
                            probe()
                        self.assertEqual(
                            raised.exception.code, expect["error"]["code"]
                        )
                        self.assertEqual(
                            list(raised.exception.required),
                            expect["error"]["required"],
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
