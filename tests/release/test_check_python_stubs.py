"""Drive scripts/check-python-stubs.py without building or installing a wheel.

The gate's judgement is pure: given an allowlist and the text stubtest printed,
which divergences are new and which recorded ones have gone stale. Everything
that needs an installed extension lives behind `run_stubtest`, which the one
end-to-end test here replaces with a canned transcript, so this suite runs on a
bare checkout.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_python_stubs", REPOSITORY_ROOT / "scripts/check-python-stubs.py"
)
assert SPEC and SPEC.loader
stubs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stubs)


MODULE = "rookie_cookies.rookie_cookies"

ALLOWLIST = f"""\
# A header paragraph about the file as a whole, separated from the first
# group by a blank line the way the shipped allowlist separates its own.

# Typing-only names a compiled module cannot define.
{MODULE}.CookieList is not present at runtime
{MODULE}.CookieObject is not present at runtime

# Pure-Python helper declared in the stub on purpose.
{MODULE}.jar is not present at runtime
"""


def summary(errors: int) -> str:
    """stubtest's closing line, spelled exactly as mypy/stubtest.py builds it."""
    if not errors:
        return "Success: no issues found in 1 module\n"
    plural = "" if errors == 1 else "s"
    return f"Found {errors} error{plural} (checked 1 module)\n"


def stubtest_output(*headlines: str, reported: int | None = None) -> str:
    """A transcript shaped like stubtest's: a headline plus quoted context.

    `reported` overrides the count in the closing summary, so a test can drive
    the case where stubtest counted more errors than the gate managed to parse.
    """
    blocks = [
        f"error: {headline}\nStub: in file /somewhere/rookie_cookies.pyi:1\nRuntime:\nMISSING\n"
        for headline in headlines
    ]
    count = len(headlines) if reported is None else reported
    return "\n".join(blocks) + "\n" + summary(count)


def colorized(output: str) -> str:
    """The same transcript as a terminal-styled mypy would print it.

    `\\x1b[1m\\x1b[31m` opens bold red and `\\x1b(B\\x1b[m` closes it; the
    charset selector in the middle is mypy's, not an invention here. Captured
    verbatim from `FORCE_COLOR=1 python -m mypy.stubtest`.
    """
    styled = output.replace("error: ", "\x1b[1m\x1b[31merror: \x1b(B\x1b[m")
    for line in ("Found ", "Success: "):
        styled = styled.replace(line, f"\x1b[1m\x1b[32m{line}")
    return styled


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

    def test_a_blank_line_ends_a_comment_block(self) -> None:
        """The file's own header is not the reason for the first group.

        Without this rule the fifteen-line preamble of the shipped allowlist
        would be recorded as the justification for all seventeen typing-only
        entries, which is worse than useless in a failure message.
        """
        for entry, reason in stubs.parse_allowlist(ALLOWLIST).items():
            self.assertNotIn("header paragraph", reason, entry)

    def test_multi_line_comment_block_joins_into_one_justification(self) -> None:
        parsed = stubs.parse_allowlist("# first half\n#   second half\nx is not present at runtime\n")
        self.assertEqual(parsed["x is not present at runtime"], "first half second half")

    def test_a_comment_detached_by_a_blank_line_does_not_count(self) -> None:
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist("# reason\n\nx is not present at runtime\n")
        self.assertIn("no comment above this entry", str(caught.exception))

    def test_entry_without_a_comment_is_rejected(self) -> None:
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist("x is not present at runtime\n")
        self.assertIn("no comment above this entry", str(caught.exception))

    def test_a_comment_that_says_nothing_is_rejected(self) -> None:
        # A bare `#` used to satisfy the "every entry has a reason" rule while
        # stating no reason at all.
        with self.assertRaises(stubs.AllowlistError) as caught:
            stubs.parse_allowlist("#\n#   \nx is not present at runtime\n")
        self.assertIn("no comment above this entry", str(caught.exception))

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

    def test_terminal_styling_does_not_hide_a_headline(self) -> None:
        """A colorized transcript must parse identically to a plain one.

        `MYPY_FORCE_COLOR`/`FORCE_COLOR` replace mypy's isatty check outright,
        so capturing the pipe is not enough: an image that exports either one
        globally used to turn every headline into `\\x1b[1m\\x1b[31merror: `,
        which matched nothing and reported the whole allowlist as stale.
        """
        plain = stubtest_output("a is not present at runtime", "b is inconsistent")
        self.assertEqual(
            stubs.stubtest_headlines(colorized(plain)),
            stubs.stubtest_headlines(plain),
        )
        self.assertEqual(stubs.stubtest_error_count(colorized(plain)), 2)


class ErrorCountTests(unittest.TestCase):
    """stubtest counts its own errors; the gate has to agree with the count."""

    def test_the_found_summary_is_read(self) -> None:
        self.assertEqual(stubs.stubtest_error_count(stubtest_output("a is gone")), 1)

    def test_a_success_summary_counts_zero(self) -> None:
        self.assertEqual(stubs.stubtest_error_count(summary(0)), 0)

    def test_output_with_no_summary_reports_none(self) -> None:
        self.assertIsNone(stubs.stubtest_error_count("error: a is gone\n"))


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

    def test_stale_allowlist_entry_fails_and_quotes_its_reason(self) -> None:
        """The reason is the one thing whoever deletes the entry needs.

        It was recorded, weakly validated, and then never printed; a stale
        entry read as an unexplained line the reader had to go look up.
        """
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
        )
        self.assertEqual(
            stubs.evaluate(self.allowlist, output),
            [
                "stale allowlist entry, this divergence no longer occurs: "
                f"{MODULE}.jar is not present at runtime "
                "(it was allowed because: Pure-Python helper declared in the stub on purpose.)"
            ],
        )

    def test_a_clean_run_retires_every_entry(self) -> None:
        failures = stubs.evaluate(self.allowlist, summary(0))
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
        failures = stubs.evaluate(self.allowlist, output)
        self.assertEqual(
            failures[0],
            "undocumented stub/runtime divergence: "
            f'{MODULE}.jar is inconsistent, stub parameter "browser" is not keyword-only',
        )
        self.assertEqual(len(failures), 2)
        self.assertTrue(failures[1].startswith("stale allowlist entry"), failures[1])

    def test_a_count_the_gate_cannot_match_fails(self) -> None:
        """The general guard against an output format the pin does not cover.

        Any parsing change that drops headlines -- colour codes, a reworded
        prefix, a new wrapper line -- shows up here as a disagreement with
        stubtest's own tally instead of a silently shorter list.
        """
        output = stubtest_output(
            f"{MODULE}.CookieList is not present at runtime",
            f"{MODULE}.CookieObject is not present at runtime",
            f"{MODULE}.jar is not present at runtime",
            reported=9,
        )
        failures = stubs.evaluate(self.allowlist, output)
        self.assertIn("stubtest reported 9 error(s) but this gate parsed 3", failures[0])

    def test_output_without_any_summary_fails(self) -> None:
        output = "error: a is not present at runtime\n"
        failures = stubs.evaluate(self.allowlist, output)
        self.assertIn("neither a 'Found N errors' nor a 'Success' summary", failures[0])

    def test_a_stub_that_does_not_compile_is_its_own_failure(self) -> None:
        """Zero errors after a build failure means nothing was checked."""
        output = (
            "error: not checking stubs due to mypy build errors:\n"
            '/pkg/rookie_cookies.pyi:620: error: Name "http" is not defined  [name-defined]\n'
        )
        failures = stubs.evaluate(self.allowlist, output)
        self.assertEqual(len(failures), 1)
        self.assertIn("stubtest checked nothing", failures[0])


class SubprocessEnvironmentTests(unittest.TestCase):
    def test_inherited_force_color_is_overridden(self) -> None:
        # MYPY_FORCE_COLOR is read before FORCE_COLOR, so pinning the former
        # off wins without unsetting a variable the surrounding CI may want.
        with mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=False):
            environment = stubs.subprocess_env()
        self.assertEqual(environment["MYPY_FORCE_COLOR"], "0")
        self.assertEqual(environment["FORCE_COLOR"], "1")

    def test_an_explicit_mypy_force_color_is_also_overridden(self) -> None:
        with mock.patch.dict(os.environ, {"MYPY_FORCE_COLOR": "1"}, clear=False):
            environment = stubs.subprocess_env()
        self.assertEqual(environment["MYPY_FORCE_COLOR"], "0")

    def test_the_rest_of_the_environment_is_inherited(self) -> None:
        with mock.patch.dict(os.environ, {"ROOKIE_PROBE": "kept"}, clear=False):
            environment = stubs.subprocess_env()
        self.assertEqual(environment["ROOKIE_PROBE"], "kept")


class CheckStubsTests(unittest.TestCase):
    """The one path that would otherwise shell out to an installed wheel."""

    def setUp(self) -> None:
        self.original = stubs.run_stubtest
        self.addCleanup(setattr, stubs, "run_stubtest", self.original)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.allowlist_path = Path(self.directory.name) / "stubtest-allowlist.txt"
        self.allowlist_path.write_text(ALLOWLIST, encoding="utf-8")

    def stub_stubtest(self, output: str, returncode: int = 1) -> None:
        # stubtest exits non-zero whenever it reports anything, so a run with
        # divergences to compare is the non-zero case, not the zero one.
        stubs.run_stubtest = lambda python, module: (returncode, output)

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

    def test_a_colorized_run_passes_end_to_end(self) -> None:
        self.stub_stubtest(
            colorized(
                stubtest_output(
                    f"{MODULE}.CookieList is not present at runtime",
                    f"{MODULE}.CookieObject is not present at runtime",
                    f"{MODULE}.jar is not present at runtime",
                )
            )
        )
        self.assertEqual(
            stubs.check_stubs(Path("python"), MODULE, self.allowlist_path), []
        )

    def test_a_crash_that_reports_nothing_is_not_read_as_a_clean_run(self) -> None:
        # A failed extension import, a segfault, or a bad module name all exit
        # non-zero having printed no `error:` line. Comparing headlines alone
        # would call every allowlist entry stale -- and once the allowlist is
        # empty, which is this design's goal, would pass outright.
        self.stub_stubtest("Traceback (most recent call last):\nImportError\n", returncode=1)
        failures = stubs.check_stubs(Path("python"), MODULE, self.allowlist_path)
        self.assertTrue(
            any("did not check the stub" in failure for failure in failures), failures
        )

    def test_an_empty_allowlist_and_a_crash_still_fails(self) -> None:
        self.allowlist_path.write_text("# nothing allowed\n", encoding="utf-8")
        self.stub_stubtest("", returncode=2)
        failures = stubs.check_stubs(Path("python"), MODULE, self.allowlist_path)
        self.assertTrue(
            any("did not check the stub" in failure for failure in failures), failures
        )

    def test_a_clean_run_with_an_empty_allowlist_passes(self) -> None:
        self.allowlist_path.write_text("# nothing allowed\n", encoding="utf-8")
        self.stub_stubtest(summary(0), returncode=0)
        self.assertEqual(
            stubs.check_stubs(Path("python"), MODULE, self.allowlist_path), []
        )

    def test_a_malformed_allowlist_fails_before_stubtest_runs(self) -> None:
        def explode(python: Path, module: str) -> tuple[int, str]:
            raise AssertionError("stubtest must not run on a malformed allowlist")

        stubs.run_stubtest = explode
        self.allowlist_path.write_text("x is not present at runtime\n", encoding="utf-8")
        failures = stubs.check_stubs(Path("python"), MODULE, self.allowlist_path)
        self.assertEqual(len(failures), 1)
        self.assertIn("no comment above this entry", failures[0])


class ShippedAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parsed = stubs.parse_allowlist(
            stubs.DEFAULT_ALLOWLIST.read_text(encoding="utf-8")
        )

    def test_the_committed_allowlist_parses(self) -> None:
        self.assertNotEqual(self.parsed, {})
        for entry, justification in self.parsed.items():
            self.assertTrue(entry.startswith(f"{MODULE}."), entry)
            self.assertNotEqual(justification, "", entry)

    def test_no_entry_inherits_the_file_header(self) -> None:
        # The header explains the file's format, not any one divergence.
        for entry, justification in self.parsed.items():
            self.assertNotIn("Each line is one", justification, entry)


if __name__ == "__main__":
    unittest.main()
