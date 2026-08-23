"""Hold `tests/python_typing/consumer.py` to the same export inventory as the runtime.

The typing fixture is checked by mypy, and mypy checks only the branch matching
the host it runs on. That leaves two blind spots a type checker cannot see:

* the fixture's *negative* half asserts that a foreign platform's browser does
  not resolve, and a misspelled name (`octo_brwoser`) produces the very same
  `attr-defined` error the real name would, so the ignore comment stays "used"
  and the fixture passes forever having asserted nothing;
* a branch can simply omit an export -- the Linux branch did omit
  `octo_browser` -- and nothing downstream notices, because the missing
  assertion is the absence of a line.

Both are inventory questions, not typing questions, so they are answered here
by parsing the fixture with `ast` and comparing what it references against
`export_contract.BROWSER_EXPORTS` and the installed `rookie_cookies.__all__`.
Nothing in this module imports or executes the fixture; it is source text.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

import rookie_cookies

from export_contract import (
    ALL_PLATFORMS,
    BROWSER_EXPORTS,
    LINUX,
    current_platform,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/python_typing/consumer.py"
PACKAGE = "rookie_cookies"

# The one function whose references are deliberately to names that must NOT
# resolve. Every other reference in the fixture is a positive assertion.
NEGATIVE_FUNCTION = "other_platforms_exports_are_hidden"


def fixture_tree() -> ast.Module:
    return ast.parse(FIXTURE.read_text(encoding="utf-8"), filename=str(FIXTURE))


def package_attributes(node: ast.AST) -> set[str]:
    """Every ``rookie_cookies.<name>`` referenced anywhere under `node`."""
    return {
        child.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute)
        and isinstance(child.value, ast.Name)
        and child.value.id == PACKAGE
    }


def guarded_platform(test: ast.expr) -> str | None:
    """The `sys.platform` value a branch guard selects, if it is one.

    Recognizes the two forms a real consumer writes, and only those: the
    equality check both checkers narrow on, and the `startswith` call Linux
    needs because `sys.platform` carries a version suffix on some builds.
    """
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and is_sys_platform(test.left)
        and isinstance(test.comparators[0], ast.Constant)
    ):
        value = test.comparators[0].value
        return value if isinstance(value, str) else None
    if (
        isinstance(test, ast.Call)
        and isinstance(test.func, ast.Attribute)
        and test.func.attr == "startswith"
        and is_sys_platform(test.func.value)
        and len(test.args) == 1
        and isinstance(test.args[0], ast.Constant)
    ):
        value = test.args[0].value
        return value if isinstance(value, str) else None
    return None


def is_sys_platform(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "platform"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def platform_branches(function: ast.FunctionDef) -> dict[str, set[str]]:
    """Map each `sys.platform` branch in `function` to the names it references.

    An `if/elif` chain is nested `If` nodes in `orelse`, so the walk follows
    that chain rather than scanning the whole body; a reference outside any
    platform guard belongs to no branch and is not collected here.
    """
    branches: dict[str, set[str]] = {}
    node: ast.stmt | None = function.body[0] if function.body else None
    for statement in function.body:
        if isinstance(statement, ast.If):
            node = statement
            break
    else:
        return branches
    while isinstance(node, ast.If):
        platform = guarded_platform(node.test)
        if platform is not None:
            names: set[str] = set()
            for statement in node.body:
                names |= package_attributes(statement)
            branches[platform] = names
        node = node.orelse[0] if len(node.orelse) == 1 else None
    return branches


def function_named(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def expected_absent(platform: str) -> set[str]:
    """Browsers the contract table says do not exist on `platform`."""
    return {
        export.name for export in BROWSER_EXPORTS if platform not in export.platforms
    }


class NegativeHalfTests(unittest.TestCase):
    """The fixture's foreign-platform assertions, checked against the table."""

    def setUp(self) -> None:
        self.tree = fixture_tree()
        function = function_named(self.tree, NEGATIVE_FUNCTION)
        self.assertIsNotNone(function, f"{FIXTURE} has no {NEGATIVE_FUNCTION}()")
        self.function: ast.FunctionDef = function  # type: ignore[assignment]
        self.branches = platform_branches(self.function)

    def test_every_supported_platform_has_a_branch(self) -> None:
        # `startswith("linux")` keys the branch by the prefix, which is the
        # same string `export_contract.LINUX` uses.
        self.assertEqual(set(self.branches), set(ALL_PLATFORMS))

    def test_each_branch_names_exactly_the_browsers_absent_there(self) -> None:
        """Catches both a narrowed branch and a typo in one comparison.

        A dropped name leaves the expected set larger; a misspelling leaves a
        name in the observed set that the contract table has never heard of.
        Neither is visible to mypy, which sees a well-formed `attr-defined`
        error either way.
        """
        for platform, referenced in sorted(self.branches.items()):
            with self.subTest(platform=platform):
                self.assertEqual(referenced, expected_absent(platform))

    def test_the_running_platform_is_covered(self) -> None:
        # The branch mypy actually checks on this host, asserted on its own so
        # a failure names the cell that is gating the PR.
        self.assertEqual(
            self.branches[current_platform()], expected_absent(current_platform())
        )

    def test_no_absent_browser_is_exported_at_runtime(self) -> None:
        # The other side of the same claim: what the fixture says is hidden
        # really is missing from the installed package.
        for name in expected_absent(current_platform()):
            with self.subTest(name=name):
                self.assertNotIn(name, rookie_cookies.__all__)
                self.assertFalse(hasattr(rookie_cookies, name))


class PositiveCoverageTests(unittest.TestCase):
    """Deleting an `assert_type` block must not silently narrow the fixture."""

    def setUp(self) -> None:
        self.tree = fixture_tree()
        negative = function_named(self.tree, NEGATIVE_FUNCTION)
        self.assertIsNotNone(negative)
        excluded = id(negative)
        self.referenced: set[str] = set()
        for node in self.tree.body:
            if id(node) != excluded:
                self.referenced |= package_attributes(node)

    def test_every_public_export_is_referenced(self) -> None:
        """No exclusion list: every name in `__all__` is reachable in a fixture.

        Type aliases and TypedDicts count when referenced in an annotation,
        which is how a consumer uses them, so nothing in `__all__` needs an
        exemption. If one ever does, add it here with the reason rather than
        weakening the comparison.
        """
        self.assertEqual(set(rookie_cookies.__all__) - self.referenced, set())

    def test_positive_references_are_real_exports(self) -> None:
        """A typo outside the negative half fails mypy, but say so precisely.

        Names from the *other* platforms' branches are legitimately present
        and absent from this host's `__all__`, so they are excused by the
        contract table rather than by a hand-written list.
        """
        known = set(rookie_cookies.__all__) | {
            export.name for export in BROWSER_EXPORTS
        }
        self.assertEqual(self.referenced - known, set())


class ContractTableTests(unittest.TestCase):
    """Guard the assumptions this module makes about `export_contract`."""

    def test_the_linux_key_matches_the_startswith_prefix(self) -> None:
        # `platform_branches` keys the Linux branch by the literal passed to
        # `startswith`, so the table's own constant has to be that same text
        # or every Linux comparison would silently compare empty sets.
        self.assertEqual(LINUX, "linux")

    def test_some_browser_is_platform_restricted(self) -> None:
        # If the table ever declared every browser on every platform, the
        # negative comparisons above would all pass vacuously.
        restricted = {
            export.name
            for export in BROWSER_EXPORTS
            if export.platforms != ALL_PLATFORMS
        }
        self.assertNotEqual(restricted, set())


if __name__ == "__main__":
    unittest.main()
