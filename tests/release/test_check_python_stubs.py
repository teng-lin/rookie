"""Drive scripts/check-python-stubs.py without building or installing a wheel.

The gate's judgement is pure: given an allowlist and the text stubtest printed,
which divergences are new and which recorded ones have gone stale. Everything
that needs an installed extension lives behind `run_stubtest`, which the one
end-to-end test here replaces with a canned transcript, so this suite runs on a
bare checkout.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_python_stubs", REPOSITORY_ROOT / "scripts/check-python-stubs.py"
)
assert SPEC and SPEC.loader
stubs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stubs)


MODULE = "rookie_cookies.rookie_cookies"

ALLOWLIST = f"""\
# Typing-only names a compiled module cannot define.
{MODULE}.CookieList is not present at runtime
{MODULE}.CookieObject is not present at runtime

# Pure-Python helper declared in the stub on purpose.
{MODULE}.jar is not present at runtime
"""


def stubtest_output(*headlines: str) -> str:
    """A transcript shaped like stubtest's: a headline plus quoted context."""
    blocks = [
        f"error: {headline}\nStub: in file /somewhere/rookie_cookies.pyi:1\nRuntime:\nMISSING\n"
        for headline in headlines
    ]
    return "\n".join(blocks) + f"\nFound {len(headlines)} errors (checked 1 module)\n"


class AllowlistParsingTests(unittest.TestCase):
    def test_entries_carry_the_comment_block_above_them(self) -> None:
        parsed = stubs.parse_allowlist(ALLOWLIST)
        self.assertEqual(
            sorted(parsed),
            [
                f"{MODULE}.CookieList is not present at runtime",
                f"{MODULE}.CookieObject is not present at runtime",
                f"{MODULE}.jar is not present at runtime",
            ],
        )
        # One block explains the run of entries beneath it; a later block
        # replaces it rather than accumulating.
        self.assertEqual(
            parsed[f"{MODULE}.CookieObject is not present at runtime"],
            "Typing-only names a compiled module cannot define.",
        )
        self.assertEqual(
            parsed[f"{MODULE}.jar is not present at runtime"],
            "Pure-Python helper declared in the stub on purpose.",
        )

    def test_multi_line_comment_block_joins_into_one_justification(self) -> None:
        parsed = stubs.parse_allowlist("# first half\n#   second half\nx is not present at runtime\n")
        self.assertEqual(parsed["x is not present at runtime"], "first half second half")

    def test_blank_lines_do_not_detach_a_comment_from_its_entries(self) -> None:
        parsed = stubs.parse_allowlist("# reason\n\nx is not present at runtime\n")
        self.assertEqual(parsed["x is not present at runtime"], "reason")

    def test_entry_without_a_comment_is_rejected(self) -> None:
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist("x is not present at runtime\n")
        self.assertIn("has no comment above it", str(caught.exception))

    def test_duplicate_entry_is_rejected(self) -> None:
        text = "# reason\nx is not present at runtime\nx is not present at runtime\n"
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist(text)
        self.assertIn("duplicate entry", str(caught.exception))

    def test_pasting_the_error_prefix_is_rejected(self) -> None:
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist("# reason\nerror: x is not present at runtime\n")
        self.assertIn("drop the", str(caught.exception))


class HeadlineExtractionTests(unittest.TestCase):
    def test_only_error_headlines_are_compared(self) -> None:
        output = stubtest_output("a is not present at runtime", "b is not present at runtime")
        self.assertEqual(
            stubs.stubtest_headlines(output),
            ["a is not present at runtime", "b is not present at runtime"],
        )

    def test_quoted_runtime_context_is_ignored(self) -> None:
        # The quoted stub/runtime lines name absolute site-packages paths, so
        # recording them would make the allowlist machine-specific.
        output = "error: a is inconsistent\nStub: in file /tmp/x.pyi:1\nRuntime:\ndef ()\n"
        self.assertEqual(stubs.stubtest_headlines(output), ["a is inconsistent"])


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowlist = stubs.parse_allowlist(ALLOWLIST)

    def test_exactly_the_recorded_divergences_pass(self) -> None:
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
            f"{MODULE}.jar is not present at runtime",
        )
        self.assertEqual(stubs.evaluate(self.allowlist, output), [])

    def test_new_divergence_fails(self) -> None:
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
            f"{MODULE}.jar is not present at runtime",
            f"{MODULE}.read is not present at runtime",
        )
        self.assertEqual(
            stubs.evaluate(self.allowlist, output),
            [f"undocumented stub/runtime divergence: {MODULE}.read is not present at runtime"],
        )

    def test_stale_allowlist_entry_fails(self) -> None:
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
        )
        self.assertEqual(
            stubs.evaluate(self.allowlist, output),
            [
                "stale allowlist entry, this divergence no longer occurs: "
                f"{MODULE}.jar is not present at runtime"
            ],
        )

    def test_a_clean_run_retires_every_entry(self) -> None:
        failures = stubs.evaluate(self.allowlist, "Success: no issues found\n")
        self.assertEqual(len(failures), 3)
        for failure in failures:
            self.assertTrue(failure.startswith("stale allowlist entry"), failure)

    def test_a_different_complaint_about_a_listed_object_still_fails(self) -> None:
        """The reason entries are whole messages rather than object names.

        `jar` is allowlisted for being absent from the extension. A signature
        drift on `jar` is a different message, and must not ride in on that.
        """
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
            f'{MODULE}.jar is inconsistent, stub parameter "browser" is not keyword-only',
        )
        self.assertEqual(
            stubs.evaluate(self.allowlist, output),
            [
                "undocumented stub/runtime divergence: "
                f'{MODULE}.jar is inconsistent, stub parameter "browser" is not keyword-only',
                "stale allowlist entry, this divergence no longer occurs: "
                f"{MODULE}.jar is not present at runtime",
            ],
        )

    def test_a_stub_that_does_not_compile_is_its_own_failure(self) -> None:
        """Zero errors after a build failure means nothing was checked."""
        output = (
            "error: not checking stubs due to mypy build errors:\n"
            '/pkg/rookie_cookies.pyi:620: error: Name "http" is not defined  [name-defined]\n'
        )
        failures = stubs.evaluate(self.allowlist, output)
        self.assertEqual(len(failures), 1)
        self.assertIn("stubtest checked nothing", failures[0])


class CheckStubsTests(unittest.TestCase):
    """The one path that would otherwise shell out to an installed wheel."""

    def setUp(self) -> None:
        self.original = stubs.run_stubtest
        self.addCleanup(setattr, stubs, "run_stubtest", self.original)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.allowlist_path = Path(self.directory.name) / "stubtest-allowlist.txt"
        self.allowlist_path.write_text(ALLOWLIST, encoding="utf-8")

    def stub_stubtest(self, output: str) -> None:
        stubs.run_stubtest = lambda python, module: output

    def test_recorded_divergences_pass_end_to_end(self) -> None:
        self.stub_stubtest(
            stubtest_output(
                f"{MODULE}.CookieList is not present at runtime",
                f"{MODULE}.CookieObject is not present at runtime",
                f"{MODULE}.jar is not present at runtime",
            )
        )
        self.assertEqual(
            stubs.check_stubs(Path("python"), MODULE, self.allowlist_path), []
        )

    def test_a_malformed_allowlist_fails_before_stubtest_runs(self) -> None:
        def explode(python: Path, module: str) -> str:
            raise AssertionError("stubtest must not run on a malformed allowlist")

        stubs.run_stubtest = explode
        self.allowlist_path.write_text("x is not present at runtime\n", encoding="utf-8")
        failures = stubs.check_stubs(Path("python"), MODULE, self.allowlist_path)
        self.assertEqual(len(failures), 1)
        self.assertIn("has no comment above it", failures[0])


class ShippedAllowlistTests(unittest.TestCase):
    def test_the_committed_allowlist_parses(self) -> None:
        parsed = stubs.parse_allowlist(stubs.DEFAULT_ALLOWLIST.read_text(encoding="utf-8"))
        self.assertNotEqual(parsed, {})
        for entry, justification in parsed.items():
            self.assertTrue(entry.startswith(f"{MODULE}."), entry)
            self.assertNotEqual(justification, "", entry)


if __name__ == "__main__":
    unittest.main()
