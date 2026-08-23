#!/usr/bin/env python3
"""Measure the Python binding's real coverage, native and pure-Python alike.

`cargo llvm-cov -p rookie-cookies-python` alone only ever sees the crate's own
`#[test]`s, which reach a fraction of the binding: every other line is behind
the PyO3 boundary and only runs when Python calls it. This script closes that
gap by instrumenting the extension *and then running the installed-wheel suite
against it*, so `tests/python` contributes to `bindings/python/src/*.rs`
coverage the way it already contributes to behavior.

The mechanism is `cargo llvm-cov show-env`: it exports a `RUSTC_WRAPPER` that
injects the coverage flags, plus the `LLVM_PROFILE_FILE` pattern the
instrumented binary writes to. Injecting through the wrapper rather than
`RUSTFLAGS` is what makes this work under maturin, which sets
`CARGO_ENCODED_RUSTFLAGS` itself and would otherwise clobber them.

The same interpreter run is measured twice at once -- LLVM records the native
side while `coverage.py` records `__init__.py` and `dto.py` -- so the two
reports always describe one execution, never two drifting ones.

    python3 scripts/run-python-coverage.py --out-dir target/python-coverage

Writes `<out-dir>/native-coverage.json` (cargo-llvm-cov) and
`<out-dir>/pure-coverage.json` (coverage.py), then enforces both sets of floors
from `coverage.toml` unless `--no-check` is passed.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_TOOLCHAIN = "nightly-2025-11-23"
# Pinned to the version test-rust.yml builds release wheels with, so the
# measured artifact takes the shipped artifact's build path.
REQUIRED_MATURIN = "1.14.1"
DEFAULT_COVERAGE = "coverage==7.15.4"

EXPORT_PREFIX = "export "

PACKAGE = "rookie-cookies-python"
NATIVE_SECTION = "python-binding-native"
PURE_SECTION = "python-binding-pure"

# Told to the suite so it can distinguish "measuring an instrumented build"
# from an ordinary run. `tests/python/test_binding_runtime.py` uses it to stand
# down one wall-clock assertion whose premise instrumentation invalidates: LLVM
# coverage counters are shared atomic increments, so threads on one code path
# contend on them and real parallelism reads as roughly 1x.
#
# A dedicated marker rather than `LLVM_PROFILE_FILE`: that variable only says
# where an instrumented binary would write its profile, so it can be exported
# by a developer for an unrelated profiling task and would then stand a test
# down against an uninstrumented wheel. This is set at the one point that
# *knows* the wheel under test was built with `-C instrument-coverage` --
# because this script built it. Any future lane that instruments the extension
# must set it too.
INSTRUMENTED_MARKER = "ROOKIE_COOKIES_INSTRUMENTED"


def run(command: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT) -> None:
    printable = " ".join(command)
    print(f"+ {printable}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env)
    if result.returncode != 0:
        raise SystemExit(f"command failed ({result.returncode}): {printable}")


def capture(command: list[str], *, cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    if result.returncode != 0:
        raise SystemExit(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return result.stdout


def unquote_sh(value: str) -> str:
    """Undo the POSIX shell quoting `show-env --sh` applies to a value.

    `str.strip("'")` is not good enough. It leaves a Windows path's
    backslashes at the mercy of whatever unquotes next, and it silently
    corrupts a checkout path containing an apostrophe, which sh quotes as the
    four-character sequence `'\''`. Handling exactly the two shapes this
    command emits -- bare, or single-quoted with that escape -- keeps
    backslashes literal in both, which a general-purpose lexer in POSIX mode
    would not.
    """
    if not value.startswith("'") or not value.endswith("'") or len(value) < 2:
        # Unquoted: sh applies no escaping here, so backslashes are literal.
        return value
    return value[1:-1].replace("'\\''", "'")


def coverage_environment(toolchain: str) -> dict[str, str]:
    """The instrumentation environment every build and test step must share.

    `RUSTUP_TOOLCHAIN` is set alongside the wrapper because `-Zcoverage-options`
    (branch coverage) is nightly-only, and maturin shells out to a bare `cargo`
    that would otherwise resolve to the default stable toolchain.
    """
    env = dict(os.environ)
    raw = capture(["cargo", f"+{toolchain}", "llvm-cov", "show-env", "--sh", "--branch"])
    for line in raw.splitlines():
        if not line.startswith(EXPORT_PREFIX):
            continue
        key, separator, value = line[len(EXPORT_PREFIX) :].partition("=")
        if not separator:
            continue
        env[key.strip()] = unquote_sh(value.strip())
    if "LLVM_PROFILE_FILE" not in env:
        raise SystemExit(
            "cargo llvm-cov show-env produced no LLVM_PROFILE_FILE; the "
            "instrumented build would silently write no profile data"
        )
    env["RUSTUP_TOOLCHAIN"] = toolchain
    return env


def require_maturin() -> None:
    """Fail early, and by name, rather than mid-build.

    This deliberately does not install anything: the interpreter running the
    script may be externally managed, and CI already installs the pinned
    maturin as its own step so the pin is visible in the workflow.
    """
    result = subprocess.run(
        [sys.executable, "-m", "maturin", "--version"], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SystemExit(
            f"maturin is not importable from {sys.executable}. "
            f"Install the pinned version first: "
            f"python -m pip install maturin=={REQUIRED_MATURIN}"
        )
    if REQUIRED_MATURIN not in result.stdout:
        raise SystemExit(
            f"expected maturin {REQUIRED_MATURIN}, found {result.stdout.strip()!r}; "
            "the measured wheel must be built the way the released wheel is"
        )


def venv_python(venv: Path) -> Path:
    """The interpreter `python -m venv` just created inside `venv`.

    Keyed off `os.name` rather than `sysconfig.get_preferred_scheme`: that
    function reports `"venv"`, not `"nt"`, whenever the *running* interpreter
    is itself inside a virtual environment, which is exactly the case in CI.
    A venv's layout follows the platform, not the parent interpreter.
    """
    scripts = "Scripts" if os.name == "nt" else "bin"
    suffix = ".exe" if os.name == "nt" else ""
    return venv / scripts / f"python{suffix}"


def build_instrumented_wheel(env: dict[str, str], dist: Path) -> Path:
    if dist.exists():
        shutil.rmtree(dist)
    run(
        [
            sys.executable,
            "-m",
            "maturin",
            "build",
            "--locked",
            "--out",
            str(dist),
            "--manifest-path",
            str(ROOT / "bindings/python/Cargo.toml"),
        ],
        env=env,
    )
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    return wheels[0]


def prepare_venv(venv: Path, wheel: Path, coverage_requirement: str) -> Path:
    if venv.exists():
        shutil.rmtree(venv)
    run([sys.executable, "-m", "venv", str(venv)])
    python = venv_python(venv)
    run([str(python), "-m", "pip", "install", "--disable-pip-version-check", "--quiet",
         str(wheel), coverage_requirement])
    return python


def measure(python: Path, env: dict[str, str], out_dir: Path) -> None:
    """Run tests/python once, recording native and pure-Python coverage together."""
    suite_env = dict(env)
    # Keep coverage.py's data files out of the working tree; the ratchet only
    # ever reads the JSON this function writes.
    suite_env["COVERAGE_FILE"] = str(out_dir / ".coverage")
    # Set here rather than in `coverage_environment`, so it describes the wheel
    # the suite imports rather than the environment a build happened to use.
    suite_env[INSTRUMENTED_MARKER] = "1"
    rcfile = str(ROOT / "bindings/python/.coveragerc")

    for stale in out_dir.glob(".coverage*"):
        stale.unlink()

    run(
        [
            str(python), "-m", "coverage", "run", f"--rcfile={rcfile}",
            "-m", "unittest", "discover", "-s", "tests/python", "-p", "test_*.py", "-v",
        ],
        env=suite_env,
    )
    # `combine` is what applies the .coveragerc [paths] aliases that map the
    # installed wheel's site-packages copies back onto the tracked sources.
    run([str(python), "-m", "coverage", "combine", f"--rcfile={rcfile}"], env=suite_env)
    run(
        [str(python), "-m", "coverage", "json", f"--rcfile={rcfile}",
         "-o", str(out_dir / "pure-coverage.json")],
        env=suite_env,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--toolchain", default=DEFAULT_TOOLCHAIN)
    parser.add_argument("--out-dir", type=Path, default=ROOT / "target/python-coverage")
    parser.add_argument("--coverage-requirement", default=DEFAULT_COVERAGE)
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="write both reports but skip the coverage.toml floors",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    require_maturin()

    env = coverage_environment(args.toolchain)
    toolchain_flag = f"+{args.toolchain}"

    # A stale profile directory would silently merge a previous run's data into
    # this one's percentages.
    run(["cargo", toolchain_flag, "llvm-cov", "clean", "--workspace"], env=env)

    # The crate's own #[test]s cover the pieces Python cannot reach directly --
    # error classification helpers and the module registration table.
    run(["cargo", toolchain_flag, "test", "-p", PACKAGE, "--locked"], env=env)

    wheel = build_instrumented_wheel(env, out_dir / "dist")
    python = prepare_venv(out_dir / "venv", wheel, args.coverage_requirement)
    measure(python, env, out_dir)

    native_report = out_dir / "native-coverage.json"
    run(
        ["cargo", toolchain_flag, "llvm-cov", "report", "--package", PACKAGE,
         "--branch", "--json", "--output-path", str(native_report)],
        env=env,
    )

    if args.no_check:
        print(f"Reports written to {out_dir}; floors skipped (--no-check).")
        return 0

    checker = str(ROOT / "scripts/check-coverage.py")
    run([sys.executable, checker, "--report", str(native_report), "--section", NATIVE_SECTION])
    run([sys.executable, checker, "--report", str(out_dir / "pure-coverage.json"),
         "--section", PURE_SECTION, "--format", "coverage-py"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
