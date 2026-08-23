"""Hold every public export to the declarative contract in `export_contract`.

The generic registry path can pass while a convenience wrapper is miswired --
`vivaldi()` reaching Chrome's store still returns cookies. These tests close
that by seeding each browser at *its own* registry root inside a synthetic home
and requiring the export to find the cookie that only that root holds.
"""

from __future__ import annotations

import ast
import inspect
import unittest
from typing import Callable
from pathlib import Path

import rookie_cookies

from export_contract import (
    ALL_PLATFORMS,
    BROWSER_EXPORTS,
    EXPORTS,
    EXPORTS_BY_NAME,
    Export,
    UnseedableBrowser,
    applicable,
    can_seed,
    current_platform,
    parameter_spec,
    seeding_exception,
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
    """Every name `rookie_cookies.pyi` declares at module level.

    Parsed rather than matched with a regex: the stub gates platform-specific
    exports behind `if sys.platform == ...:` blocks, so a pattern permissive
    enough to see `safari` nested one level deep is also permissive enough to
    see every parameter, TypedDict field, and class attribute in the file --
    which would make `in_stub` pass for any export sharing a name with, say,
    `timeout` or `code`. Walking `ast.If` bodies finds exactly the nested
    module-level declarations and nothing else.
    """
    module = ast.parse(_STUB.read_text(encoding="utf-8"))
    names: set[str] = set()

    def collect(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node, ast.Assign):
                names.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )
            elif isinstance(node, ast.If):
                collect(node.body)
                collect(node.orelse)

    collect(module.body)
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

    def test_each_row_declares_what_its_export_actually_is(self) -> None:
        """Per row, not per set.

        Comparing the set of kinds in use against the known set cannot fail on
        a row that names the wrong one -- `Export("version", kind="class")`
        passes as long as some other row still says "function". This checks
        each row against the object it names.
        """
        checks: dict[str, Callable[[object], bool]] = {
            "function": lambda value: callable(value) and not inspect.isclass(value),
            "class": inspect.isclass,
            "module": inspect.ismodule,
            "constant": lambda value: isinstance(value, (int, float, str)),
            # `Literal[...]` aliases and `TypedDict`s are neither plain values
            # nor ordinary classes; what they share is that no caller invokes
            # them, which is what separates them from "function".
            "alias": lambda value: value is not None,
        }
        self.assertEqual(set(checks), {export.kind for export in EXPORTS})
        for export in EXPORTS:
            if not applicable(export):
                continue
            with self.subTest(export=export.name, kind=export.kind):
                self.assertIn(export.kind, checks, export.name)
                value = getattr(rookie_cookies, export.name)
                self.assertTrue(
                    checks[export.kind](value),
                    f"{export.name} is declared {export.kind!r} but is a "
                    f"{type(value).__name__}",
                )

    def test_seeding_exceptions_match_what_the_registry_can_actually_seed(self) -> None:
        """Both directions, so an exception cannot silence a real failure.

        A browser this suite cannot seed here needs a stated reason, and a
        browser it *can* seed here must not carry one -- otherwise adding an
        exception would be a way to opt a working export out of its success
        path.
        """
        for export in BROWSER_EXPORTS:
            if not applicable(export):
                continue
            reason = seeding_exception(export)
            seedable = can_seed(export.name)
            with self.subTest(export=export.name, platform=current_platform()):
                if seedable:
                    self.assertIsNone(
                        reason,
                        f"{export.name} is seedable on {current_platform()}; "
                        "delete its seeding exception rather than skipping the "
                        "success probe",
                    )
                    continue
                self.assertIsNotNone(
                    reason,
                    f"{export.name} cannot be seeded on {current_platform()} and "
                    "has no stated reason",
                )
                assert reason is not None
                self.assertGreaterEqual(
                    len(reason.split()),
                    6,
                    "a seeding exception needs a real reason, not a label",
                )

    def test_seeding_exceptions_are_consistent_on_every_platform(self) -> None:
        """The same check as above, for the two platforms this host is not.

        Seedability is a property of the registry alone, so one host can prove
        all three. Without this, a contradiction on another platform surfaces
        only when that platform's CI job runs -- which is how `arc` came to be
        declared seedable on Linux, where it has no registry root at all, and
        on Windows, where its root is an MSIX glob.
        """
        for platform in sorted(ALL_PLATFORMS):
            for export in BROWSER_EXPORTS:
                if platform not in export.platforms:
                    continue
                reason = export.seeding_exceptions.get(platform)
                with self.subTest(export=export.name, platform=platform):
                    if can_seed(export.name, platform):
                        self.assertIsNone(
                            reason,
                            f"{export.name} is seedable on {platform}; delete its "
                            "seeding exception rather than skipping the success probe",
                        )
                    else:
                        self.assertIsNotNone(
                            reason,
                            f"{export.name} cannot be seeded on {platform} and has "
                            "no stated reason",
                        )

    def test_every_platform_conditional_export_declares_its_platforms(self) -> None:
        # `platforms` describes where the export EXISTS, which is the binding's
        # cfg gating -- not where the registry happens to place the browser.
        # Conflating the two is what let `arc` be declared macOS/Windows-only
        # while `__init__.py` exports it everywhere.
        for export in BROWSER_EXPORTS:
            with self.subTest(export=export.name):
                self.assertEqual(
                    export.name in rookie_cookies.__all__,
                    applicable(export),
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
        probed = 0
        for export in EXPORTS:
            if not applicable(export) or export.success is None:
                continue
            if seeding_exception(export) is not None:
                continue
            probed += 1
            with self.subTest(export=export.name):
                self._assert_success(export)
        # A guard against the whole loop silently emptying: a filter bug or a
        # platform-detection bug would otherwise report `ok` having run nothing.
        self.assertGreater(probed, 20, "the success-probe set collapsed")

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
                    "Add a seeding_exceptions entry for this platform instead."
                )
        problem = export.expect(value)
        self.assertIsNone(problem, f"{export.name}: {problem}")


class ExportFailurePathTest(unittest.TestCase):
    """One call per export that must raise the classified exception it declares."""

    def test_failure_probes(self) -> None:
        probed = 0
        for export in EXPORTS:
            if not applicable(export) or export.failure is None:
                continue
            probed += 1
            with self.subTest(export=export.name):
                self._assert_failure(export)
        self.assertGreater(probed, 20, "the failure-probe set collapsed")

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
