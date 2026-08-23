"""Unit tests for `scripts/run-python-coverage.py`'s host-dependent helpers.

Only the parts that can be wrong without a build: the shell unquoting applied
to `cargo llvm-cov show-env` output, the venv layout the script expects, and
the instrumentation marker the measured suite reads. The first two were
measured on macOS during development and both have a Windows-only failure
mode, which is exactly why they are pinned here; the third is a name two files
have to agree on with nothing but convention holding them together.
"""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import tempfile
from typing import Optional
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_python_coverage", ROOT / "scripts/run-python-coverage.py"
)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def environment_names_read(source: str) -> set[str]:
    """Every environment variable `source` actually looks up, from its AST.

    Deliberately not a substring search. The marker below appears in prose and
    in a skip message as well as in the lookup, so a textual match would still
    be satisfied after the lookup itself was deleted or renamed -- which is the
    one thing worth detecting. Covers the three shapes a lookup can take:
    `environ.get(name)`, `environ[name]`, and `name in environ`.
    """

    def reads_environ(node: ast.AST) -> bool:
        return (isinstance(node, ast.Attribute) and node.attr == "environ") or (
            isinstance(node, ast.Name) and node.id == "environ"
        )

    def literal(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        name = None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and reads_environ(node.func.value)
            and node.args
        ):
            name = literal(node.args[0])
        elif isinstance(node, ast.Subscript) and reads_environ(node.value):
            name = literal(node.slice)
        elif (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and reads_environ(node.comparators[0])
        ):
            name = literal(node.left)
        if name is not None:
            names.add(name)
    return names


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


class InstrumentationMarkerTests(unittest.TestCase):
    """The suite learns the wheel is instrumented only from this variable.

    `tests/python/test_binding_runtime.py` stands its parallel-speedup bound
    down when it sees `ROOKIE_COOKIES_INSTRUMENTED=1`, because LLVM's shared
    atomic counters make that measurement meaningless. The two sides agree by
    name alone, so both halves of that agreement are pinned here: if the marker
    stops being exported, or the name drifts, the bound is measured against an
    instrumented wheel again and issue #337 returns.
    """

    def _envs_measure_passes_to_its_subprocesses(self) -> list[dict[str, str]]:
        captured: list[dict[str, str]] = []

        def fake_run(
            command: list[str],
            *,
            env: dict[str, str] | None = None,
            cwd: Path | None = None,
        ) -> None:
            captured.append(dict(env or {}))

        original = runner.run
        runner.run = fake_run
        try:
            with tempfile.TemporaryDirectory(prefix="rookie-coverage-marker-") as temp:
                runner.measure(Path("python"), {}, Path(temp))
        finally:
            runner.run = original
        return captured

    def test_every_suite_subprocess_is_told_the_wheel_is_instrumented(self) -> None:
        envs = self._envs_measure_passes_to_its_subprocesses()
        self.assertTrue(envs, "measure() ran no subprocess to inspect")
        for index, env in enumerate(envs):
            with self.subTest(command=index):
                self.assertEqual(env.get(runner.INSTRUMENTED_MARKER), "1")

    def test_the_marker_name_is_the_one_the_python_suite_reads(self) -> None:
        source = (ROOT / "tests/python/test_binding_runtime.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            runner.INSTRUMENTED_MARKER,
            environment_names_read(source),
            "tests/python/test_binding_runtime.py never looks "
            f"{runner.INSTRUMENTED_MARKER} up in os.environ; the exporter and "
            "the reader have drifted",
        )

    def test_a_mention_outside_a_lookup_does_not_count(self) -> None:
        """Why the AST walk exists: a substring search would pass on this.

        The marker legitimately appears in that file's comments and in the
        skip message. If the lookup itself were deleted or renamed and only
        the prose left behind -- exactly the drift the test above claims to
        catch -- a textual search would still be satisfied.
        """
        decoy = (
            "# ROOKIE_COOKIES_INSTRUMENTED explains the skip\n"
            'REASON = "set ROOKIE_COOKIES_INSTRUMENTED=1 to stand the bound down"\n'
        )
        self.assertEqual(environment_names_read(decoy), set())

    def test_every_lookup_shape_is_recognized(self) -> None:
        for source in (
            'import os\nflag = os.environ.get("MARKER") == "1"\n',
            'import os\nflag = os.environ["MARKER"]\n',
            'import os\nflag = "MARKER" in os.environ\n',
            'from os import environ\nflag = environ.get("MARKER")\n',
        ):
            with self.subTest(source=source.splitlines()[-1]):
                self.assertEqual(environment_names_read(source), {"MARKER"})


if __name__ == "__main__":
    unittest.main()
