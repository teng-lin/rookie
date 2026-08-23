"""Unit tests for `scripts/run-python-coverage.py`'s host-dependent helpers.

Only the parts that can be wrong without a build: the shell unquoting applied
to `cargo llvm-cov show-env` output, and the venv layout the script expects.
Both were measured on macOS during development and both have a Windows-only
failure mode, which is exactly why they are pinned here.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_python_coverage", ROOT / "scripts/run-python-coverage.py"
)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class UnquoteShellValueTests(unittest.TestCase):
    def test_a_bare_value_passes_through(self) -> None:
        self.assertEqual(
            runner.unquote_sh("/home/runner/.cargo/bin/cargo-llvm-cov"),
            "/home/runner/.cargo/bin/cargo-llvm-cov",
        )

    def test_single_quotes_are_stripped(self) -> None:
        self.assertEqual(
            runner.unquote_sh("'/tmp/target/rookie-%p-%10m.profraw'"),
            "/tmp/target/rookie-%p-%10m.profraw",
        )

    def test_an_unquoted_windows_path_keeps_every_backslash(self) -> None:
        # A general-purpose POSIX lexer eats these, which would leave Cargo
        # trying to run `C:UsersrunneradminX`.
        path = r"C:\Users\runneradmin\.cargo\bin\cargo-llvm-cov.exe"
        self.assertEqual(runner.unquote_sh(path), path)

    def test_a_quoted_windows_path_with_spaces_keeps_every_backslash(self) -> None:
        self.assertEqual(
            runner.unquote_sh(r"'C:\Program Files\rust\cargo-llvm-cov.exe'"),
            r"C:\Program Files\rust\cargo-llvm-cov.exe",
        )

    def test_an_apostrophe_in_the_checkout_path_is_decoded(self) -> None:
        # sh renders `/home/o'brien/target` as `'/home/o'\''brien/target'`.
        self.assertEqual(
            runner.unquote_sh("'/home/o'\\''brien/target'"),
            "/home/o'brien/target",
        )

    def test_a_lone_quote_is_not_treated_as_a_quoted_value(self) -> None:
        self.assertEqual(runner.unquote_sh("'"), "'")


class VenvLayoutTests(unittest.TestCase):
    def test_the_layout_follows_the_platform_not_the_parent_interpreter(self) -> None:
        # `sysconfig.get_preferred_scheme("prefix")` reports "venv" whenever the
        # running interpreter is itself in a virtual environment -- which it is
        # in CI -- so keying off it would pick `bin` on Windows.
        expected = "Scripts" if os.name == "nt" else "bin"
        self.assertEqual(runner.venv_python(Path("venv")).parent.name, expected)

    def test_the_executable_carries_a_suffix_only_on_windows(self) -> None:
        suffix = ".exe" if os.name == "nt" else ""
        self.assertEqual(runner.venv_python(Path("venv")).name, f"python{suffix}")


if __name__ == "__main__":
    unittest.main()
