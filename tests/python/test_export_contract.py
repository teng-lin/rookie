"""Hold every public export to the declarative contract in `export_contract`.

The generic registry path can pass while a convenience wrapper is miswired --
`vivaldi()` reaching Chrome's store still returns cookies. These tests close
that by seeding each browser at *its own* registry root inside a synthetic home
and requiring the export to find the cookie that only that root holds.
"""

from __future__ import annotations

import inspect
import re
import unittest
from pathlib import Path

import rookie_cookies

from export_contract import (
    EXPORTS,
    EXPORTS_BY_NAME,
    Export,
    UnseedableBrowser,
    applicable,
    current_platform,
    parameter_spec,
    synthetic_home,
)

_STUB = Path(rookie_cookies.__file__).with_name("rookie_cookies.pyi")

_CLASS_MEMBERS = {
    "CancellationHandle": {
        "cancel": "(self, /)",
        "is_cancelled": "(self, /)",
    },
    "ReadResult": {
        "as_jar": "(self)",
        "as_list": "(self, /)",
        "detailed_cookies": "(self, /)",
        "header": (
            "(self, context=None, /, *, url=None, top_level_site=None, resource=None, "
            "method=None, user_context_id=None, private_browsing_id=None, now=None)"
        ),
        "browser_id": None,
        "profile_id": None,
        "warnings": None,
    },
    "ReadWarning": {"code": None, "count": None},
}


def _stub_declarations() -> set[str]:
    """Every name `rookie_cookies.pyi` declares.

    Leading indentation is allowed because the stub expresses platform gating
    with `if platform == ...:` blocks, so `safari` and `opera_gx` are nested one
    level deep while being module-level declarations all the same.
    """
    text = _STUB.read_text(encoding="utf-8")
    pattern = re.compile(
        r"^\s*(?:def (?P<function>\w+)\(|class (?P<class>\w+)[\(:]|(?P<value>\w+)\s*[:=])",
        re.MULTILINE,
    )
    names: set[str] = set()
    for match in pattern.finditer(text):
        names.update(value for value in match.groupdict().values() if value)
    return names


class ExportContractTest(unittest.TestCase):
    def test_every_public_export_has_a_contract_row(self) -> None:
        declared = {export.name for export in EXPORTS if applicable(export)}
        self.assertEqual(declared, set(rookie_cookies.__all__))

    def test_contract_rows_are_unique(self) -> None:
        self.assertEqual(len(EXPORTS_BY_NAME), len(EXPORTS))

    def test_runtime_presence_matches_declared_platforms(self) -> None:
        for export in EXPORTS:
            with self.subTest(export=export.name):
                self.assertEqual(
                    hasattr(rookie_cookies, export.name),
                    applicable(export),
                    f"{export.name} on {current_platform()}",
                )

    def test_stub_declares_every_export_it_claims_to(self) -> None:
        declarations = _stub_declarations()
        for export in EXPORTS:
            if not applicable(export):
                continue
            with self.subTest(export=export.name):
                self.assertEqual(
                    export.name in declarations,
                    export.in_stub,
                    f"{export.name} stub presence disagrees with the contract",
                )

    def test_parameter_shapes_match_the_contract(self) -> None:
        for export in EXPORTS:
            if not applicable(export) or export.signature is None:
                continue
            with self.subTest(export=export.name):
                self.assertEqual(
                    parameter_spec(getattr(rookie_cookies, export.name)),
                    export.signature,
                )

    def test_class_members_match_the_contract(self) -> None:
        for name, members in _CLASS_MEMBERS.items():
            cls = getattr(rookie_cookies, name)
            public = {member for member in dir(cls) if not member.startswith("_")}
            with self.subTest(cls=name):
                self.assertEqual(public, set(members))
            for member, signature in members.items():
                with self.subTest(cls=name, member=member):
                    attribute = inspect.getattr_static(cls, member)
                    if signature is None:
                        self.assertFalse(callable(attribute), f"{name}.{member}")
                        continue
                    self.assertEqual(parameter_spec(getattr(cls, member)), signature)

    def test_kinds_are_from_the_known_set(self) -> None:
        self.assertEqual(
            {export.kind for export in EXPORTS},
            {"function", "class", "constant", "alias", "module"},
        )

    def test_seeding_exceptions_are_documented(self) -> None:
        for export in EXPORTS:
            if export.seeding_exception is None:
                continue
            with self.subTest(export=export.name):
                self.assertIsNone(
                    export.success,
                    "a documented seeding exception must not also carry a success probe",
                )
                self.assertGreaterEqual(
                    len(export.seeding_exception.split()),
                    6,
                    "a seeding exception needs a real reason, not a label",
                )

    def test_functions_without_a_failure_probe_say_why(self) -> None:
        for export in EXPORTS:
            if export.kind != "function" or export.failure is not None:
                continue
            with self.subTest(export=export.name):
                self.assertNotEqual(
                    export.notes, "", f"{export.name} needs a note explaining the omission"
                )


class ExportSuccessPathTest(unittest.TestCase):
    """One call per export that must return the declared shape."""

    def test_success_probes(self) -> None:
        for export in EXPORTS:
            if not applicable(export) or export.success is None:
                continue
            with self.subTest(export=export.name):
                self._assert_success(export)

    def _assert_success(self, export: Export) -> None:
        self.assertIsNotNone(
            export.expect, f"{export.name} declares a success probe with no expectation"
        )
        assert export.expect is not None and export.success is not None
        with synthetic_home() as home:
            try:
                value = export.success(home)
            except UnseedableBrowser as error:  # pragma: no cover - contract guard
                self.fail(
                    f"{export.name} has a success probe but cannot be seeded: {error}. "
                    "Give it a seeding_exception instead."
                )
        problem = export.expect(value)
        self.assertIsNone(problem, f"{export.name}: {problem}")


class ExportFailurePathTest(unittest.TestCase):
    """One call per export that must raise the classified exception it declares."""

    def test_failure_probes(self) -> None:
        for export in EXPORTS:
            if not applicable(export) or export.failure is None:
                continue
            with self.subTest(export=export.name):
                self._assert_failure(export)

    def _assert_failure(self, export: Export) -> None:
        failure = export.failure
        self.assertIsNotNone(failure)
        assert failure is not None
        with synthetic_home() as home:
            with self.assertRaises(failure.exception) as raised:
                failure.probe(home)
        error = raised.exception
        if failure.kind is not None:
            self.assertEqual(getattr(error, "kind", None), failure.kind, export.name)
        if failure.code is not None:
            self.assertEqual(getattr(error, "code", None), failure.code, export.name)


if __name__ == "__main__":
    unittest.main()
