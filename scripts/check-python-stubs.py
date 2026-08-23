#!/usr/bin/env python3
"""Gate the Python binding's runtime/stub compatibility against a real wheel.

Two checks, both run against an *installed* `rookie_cookies`, because that is
the only artifact a downstream consumer's type checker ever sees:

* `mypy.stubtest` compares `rookie_cookies.rookie_cookies.pyi` to the compiled
  PyO3 module it names, and every divergence must be listed -- with a stated
  reason -- in `bindings/python/stubtest-allowlist.txt`;
* mypy type-checks `tests/python_typing/consumer.py`, a fixture written the way
  a downstream user writes code, so the stub is proven *usable* and not merely
  self-consistent.

Why the allowlist holds whole stubtest messages rather than object names
----------------------------------------------------------------------
`stubtest --allowlist` matches its entries against the *object path* only
(`mypy/stubtest.py`, `allowlist_regexes[w].fullmatch(error.object_desc)`), so
one entry for `read` waves through every present and future complaint about
`read` -- a return type that changed, an argument that vanished, the lot. That
is the opposite of a ratchet. This script therefore drives stubtest without
`--allowlist` and diffs the full set of its error headlines against the file,
which makes the gate symmetric and self-cleaning:

* an unlisted divergence fails (new drift);
* a listed divergence that no longer occurs fails (stale entry, delete it);
* a *different* complaint about an already-listed object fails, because its
  headline text differs from the recorded one.

`--ignore-unused-allowlist` is deliberately not used, and not needed: the stale
half of the diff above is exactly what that flag would suppress.

    python3 scripts/check-python-stubs.py --python .venv/bin/python
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]

# Pinned like `maturin==1.14.1` in run-python-coverage.py: stubtest's and
# mypy's diagnostic wording is part of this gate's contract, so an unpinned
# upgrade would rewrite the allowlist's expected text under us.
DEFAULT_MYPY = "mypy==2.3.1"

DEFAULT_MODULE = "rookie_cookies.rookie_cookies"
DEFAULT_ALLOWLIST = ROOT / "bindings/python/stubtest-allowlist.txt"
DEFAULT_CONSUMER = ROOT / "tests/python_typing/consumer.py"

ERROR_PREFIX = "error: "

# stubtest emits this instead of checking anything when the stub does not
# type-check on its own. It is a hard failure with its own message because the
# error count that follows is zero, which otherwise reads as "all clear".
BUILD_ERROR_MARKER = "not checking stubs due to mypy build errors"


class AllowlistError(ValueError):
    """The allowlist file does not follow the documented format."""


def parse_allowlist(text: str) -> dict[str, str]:
    """Map each expected stubtest headline to the reason it is allowed.

    The format is a stubtest error message per line -- verbatim, minus the
    leading ``error: `` -- under a ``#`` comment block that says why the
    divergence is intentional. One comment block covers the run of entries
    beneath it, so a group of seventeen identical-in-kind divergences is
    explained once rather than seventeen times, but no entry may appear before
    any comment: every line in the file has a stated reason above it.
    """
    entries: dict[str, str] = {}
    justification: list[str] = []
    trailing_entries = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if trailing_entries:
                justification = []
                trailing_entries = False
            justification.append(line.lstrip("#").strip())
            continue
        if not justification:
            raise AllowlistError(f"line {number}: entry has no comment above it: {line}")
        if line in entries:
            raise AllowlistError(f"line {number}: duplicate entry: {line}")
        if line.startswith(ERROR_PREFIX):
            raise AllowlistError(
                f"line {number}: drop the {ERROR_PREFIX!r} prefix, entries are bare messages: {line}"
            )
        entries[line] = " ".join(justification)
        trailing_entries = True
    return entries


def stubtest_headlines(output: str) -> list[str]:
    """Every ``error: `` headline stubtest printed, in the order printed.

    stubtest wraps each error in several continuation lines that quote the stub
    and the runtime object, and those quote absolute paths into site-packages.
    Only the headline is stable enough to record, so only the headline is
    compared; the full output is reprinted whenever the gate fails.
    """
    return [
        line[len(ERROR_PREFIX) :].strip()
        for line in output.splitlines()
        if line.startswith(ERROR_PREFIX)
    ]


def evaluate(allowlist: dict[str, str], output: str) -> list[str]:
    """Failures for one stubtest run: unlisted divergences and stale entries."""
    if BUILD_ERROR_MARKER in output:
        return [
            "stubtest checked nothing: the stub does not type-check on its own "
            f"({BUILD_ERROR_MARKER}). Fix the stub errors quoted below first."
        ]
    observed = stubtest_headlines(output)
    failures = [
        f"undocumented stub/runtime divergence: {headline}"
        for headline in observed
        if headline not in allowlist
    ]
    seen = set(observed)
    failures.extend(
        f"stale allowlist entry, this divergence no longer occurs: {entry}"
        for entry in allowlist
        if entry not in seen
    )
    return failures


def display(path: Path) -> str:
    """Repo-relative when it can be, absolute otherwise (an overridden --allowlist)."""
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    printable = " ".join(command)
    print(f"+ {printable}", flush=True)
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")


def mypy_version(python: Path, requirement: str) -> str:
    result = run([str(python), "-m", "mypy", "--version"])
    if result.returncode != 0:
        raise SystemExit(
            f"{python} cannot run mypy. Install the pinned version with:\n"
            f"  {python} -m pip install {requirement}\n"
            "or re-run this script with --install-mypy."
        )
    # "mypy 2.3.1 (compiled: yes)" -> "2.3.1"
    return result.stdout.split()[1]


def require_pinned_mypy(python: Path, requirement: str, install: bool) -> None:
    expected = requirement.partition("==")[2]
    if install:
        installation = run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                            "--quiet", requirement])
        if installation.returncode != 0:
            raise SystemExit(f"could not install {requirement}:\n{installation.stderr}")
    found = mypy_version(python, requirement)
    if expected and found != expected:
        raise SystemExit(
            f"{python} has mypy {found}, this gate is pinned to {expected}. "
            "Pass --install-mypy, or --mypy-requirement to move the pin deliberately."
        )


def run_stubtest(python: Path, module: str) -> str:
    result = run([str(python), "-m", "mypy.stubtest", module])
    return result.stdout + result.stderr


def check_stubs(python: Path, module: str, allowlist_path: Path) -> list[str]:
    try:
        allowlist = parse_allowlist(allowlist_path.read_text(encoding="utf-8"))
    except AllowlistError as error:
        return [f"{display(allowlist_path)}: {error}"]
    output = run_stubtest(python, module)
    failures = evaluate(allowlist, output)
    if failures:
        print(output, file=sys.stderr)
    return failures


def check_consumer(python: Path, consumer: Path) -> list[str]:
    """Type-check the downstream-consumer fixture against the installed wheel.

    `--strict` is what gives the fixture's negative half its teeth: it turns on
    `--warn-unused-ignores`, so a `# type: ignore[attr-defined]` on a foreign
    platform's export fails the build the moment that export stops being
    hidden.
    """
    with tempfile.TemporaryDirectory(prefix="rookie-mypy-cache-") as cache:
        result = run([
            str(python), "-m", "mypy", "--strict", "--no-incremental",
            f"--cache-dir={cache}", str(consumer),
        ])
    if result.returncode == 0:
        return []
    print(result.stdout + result.stderr, file=sys.stderr)
    return [
        f"{display(consumer)} does not type-check against the installed wheel "
        "(see mypy output above)"
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--python",
        type=Path,
        default=Path(sys.executable),
        help="interpreter with the rookie-cookies wheel installed (default: this one)",
    )
    parser.add_argument("--module", default=DEFAULT_MODULE)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--consumer", type=Path, default=DEFAULT_CONSUMER)
    parser.add_argument("--mypy-requirement", default=DEFAULT_MYPY)
    parser.add_argument(
        "--install-mypy",
        action="store_true",
        help="pip-install the pinned mypy into --python before checking",
    )
    parser.add_argument(
        "--skip-consumer",
        action="store_true",
        help="run only the stubtest half (for regenerating the allowlist)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # Deliberately not `.resolve()`: a venv's bin/python is a symlink to the
    # base interpreter, and resolving it would run the check against a Python
    # that has neither the wheel nor mypy installed.
    python = Path(os.path.abspath(args.python))
    require_pinned_mypy(python, args.mypy_requirement, args.install_mypy)

    failures = check_stubs(python, args.module, args.allowlist)
    if not args.skip_consumer:
        failures.extend(check_consumer(python, args.consumer))

    if failures:
        print("Python stub compatibility check failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Python stub compatibility check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
