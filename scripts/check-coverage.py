#!/usr/bin/env python3
"""Enforce ratcheted coverage floors for LLVM and coverage.py reports.

One script serves three lanes because a floor is a floor regardless of which
instrument measured it:

* the workspace Cargo lane (`cargo llvm-cov --workspace`), which reads the
  root `[workspace]`/`[files]` tables;
* the Python binding's native lane (`--section python-binding-native`), whose
  LLVM report is produced by `scripts/run-python-coverage.py` and includes the
  installed-wheel suite's calls across the PyO3 boundary;
* the Python binding's pure-Python lane (`--section python-binding-pure`,
  `--format coverage-py`), measured by `coverage.py --branch`.

Both report formats are normalized to `{path: {"lines": pct, "branches": pct}}`
before enforcement, so the floor logic and its failure messages are identical.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("check-coverage.py requires Python 3.11 or newer") from error


ROOT = Path(__file__).resolve().parents[1]

LLVM_FORMAT = "llvm"
COVERAGE_PY_FORMAT = "coverage-py"

# `[workspace]` is the historical name of the root aggregate table; sections
# added later use `totals`. Both mean "the floors for this report's grand
# total", and whichever one a scope declares also names it in failure text.
AGGREGATE_KEYS = ("workspace", "totals")


class ReportError(ValueError):
    """The coverage report is missing something a floor needs to read."""


def percentage(summary: dict[str, object], metric: str) -> float:
    value = summary.get(metric)
    if not isinstance(value, dict) or not isinstance(value.get("percent"), (int, float)):
        raise ValueError(f"coverage report omitted {metric}.percent")
    return float(value["percent"])


def normalized_repo_path(filename: str, root: Path) -> str | None:
    path = Path(filename)
    if not path.is_absolute():
        path = root / path
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def ratio(covered: object, total: object, *, context: str, empty_is_total: bool) -> float:
    """Percentage for a coverage.py counter pair.

    `empty_is_total` says what a zero denominator means. For branches it is
    100%: a file with no branches has covered every branch it has, and
    reporting 0% would make an unbranching module impossible to gate. For
    statements it is an error -- a gated Python file always has statements, so
    a zero there means the report did not describe the file this floor names,
    and scoring it 100% would retire the floor silently.
    """
    if not isinstance(covered, (int, float)) or not isinstance(total, (int, float)):
        raise ReportError(f"coverage report omitted {context}")
    if total == 0:
        if empty_is_total:
            return 100.0
        raise ReportError(f"coverage report has no {context} to measure")
    return float(covered) / float(total) * 100.0


def normalize_llvm(report: dict[str, object], root: Path) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    data = report.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ReportError("coverage report must contain exactly one data object")
    payload = data[0]
    totals = payload.get("totals")
    files = payload.get("files")
    if not isinstance(totals, dict) or not isinstance(files, list):
        raise ReportError("coverage report omitted totals or files")

    aggregate = {metric: percentage(totals, metric) for metric in ("lines", "branches")}
    summaries: dict[str, dict[str, float]] = {}
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            continue
        repo_path = normalized_repo_path(entry["filename"], root)
        summary = entry.get("summary")
        if repo_path is not None and isinstance(summary, dict):
            summaries[repo_path] = {
                metric: percentage(summary, metric) for metric in ("lines", "branches")
            }
    return aggregate, summaries


def coverage_py_metrics(summary: dict[str, object], *, context: str) -> dict[str, float]:
    """Derive separate line and branch percentages from a coverage.py summary.

    coverage.py's own `percent_covered` blends statements and branches into a
    single number once `branch = True`, which cannot express the two floors
    this ratchet keeps. The underlying counters can, so read those instead.
    """
    return {
        "lines": ratio(
            summary.get("covered_lines"),
            summary.get("num_statements"),
            context=f"{context} statement counters",
            empty_is_total=False,
        ),
        "branches": ratio(
            summary.get("covered_branches"),
            summary.get("num_branches"),
            context=f"{context} branch counters",
            empty_is_total=True,
        ),
    }


def normalize_coverage_py(report: dict[str, object], root: Path) -> tuple[dict[str, float], dict[str, dict[str, float]]]:
    totals = report.get("totals")
    files = report.get("files")
    if not isinstance(totals, dict) or not isinstance(files, dict):
        raise ReportError("coverage report omitted totals or files")

    aggregate = coverage_py_metrics(totals, context="totals")
    summaries: dict[str, dict[str, float]] = {}
    for filename, entry in files.items():
        if not isinstance(filename, str) or not isinstance(entry, dict):
            continue
        summary = entry.get("summary")
        repo_path = normalized_repo_path(filename, root)
        if repo_path is not None and isinstance(summary, dict):
            summaries[repo_path] = coverage_py_metrics(summary, context=repo_path)
    return aggregate, summaries


NORMALIZERS = {LLVM_FORMAT: normalize_llvm, COVERAGE_PY_FORMAT: normalize_coverage_py}


SCOPE_KEYS = frozenset({*AGGREGATE_KEYS, "files"})


def select_scope(config: dict[str, object], section: str | None) -> dict[str, object]:
    """The tables holding one lane's floors, verified to hold at least one.

    A scope that declares nothing enforceable is rejected rather than passed:
    a typo -- `[python-binding-native.total]`, a renamed section -- otherwise
    parses fine, contributes no floors, and prints "Coverage ratchet passed"
    having checked nothing at all. Unknown keys are rejected for the same
    reason, since that is what a misspelled `totals` looks like from here.
    """
    if section is None:
        return config
    scope = config.get(section)
    if not isinstance(scope, dict):
        raise ReportError(f"coverage config has no [{section}] table")
    unknown = sorted(set(scope) - SCOPE_KEYS)
    if unknown:
        raise ReportError(
            f"coverage config [{section}] has unknown key(s) {unknown}; "
            f"expected any of {sorted(SCOPE_KEYS)}"
        )
    has_aggregate = any(isinstance(scope.get(key), dict) for key in AGGREGATE_KEYS)
    if not has_aggregate and not scope.get("files"):
        raise ReportError(
            f"coverage config [{section}] declares no floors, so it would "
            "enforce nothing"
        )
    return scope


def enforce(
    config: dict[str, object],
    report: dict[str, object],
    root: Path,
    *,
    section: str | None = None,
    report_format: str = LLVM_FORMAT,
) -> list[str]:
    try:
        scope = select_scope(config, section)
        aggregate, summaries = NORMALIZERS[report_format](report, root)
    except ValueError as error:
        # `ReportError` subclasses `ValueError`, and so does `percentage`'s
        # complaint about an LLVM summary missing `lines.percent`. Both are the
        # same thing -- a report this ratchet cannot read -- and both must come
        # back as a failure rather than a traceback.
        return [str(error)]

    prefix = "" if section is None else f"{section} "
    failures: list[str] = []

    for aggregate_key in AGGREGATE_KEYS:
        floors = scope.get(aggregate_key)
        if floors is None:
            continue
        if not isinstance(floors, dict):
            return [f"coverage config {prefix}[{aggregate_key}] must be a table"]
        for metric, floor in floors.items():
            if metric not in aggregate:
                failures.append(f"{prefix}{aggregate_key}: unknown metric {metric!r}")
                continue
            observed = aggregate[metric]
            if observed < float(floor):
                failures.append(
                    f"{prefix}{aggregate_key} {metric}: {observed:.2f}% is below {float(floor):.2f}%"
                )

    configured_files = scope.get("files", {})
    if not isinstance(configured_files, dict):
        return ["coverage config [files] must be a table"]
    for filename, floors in configured_files.items():
        if filename not in summaries:
            failures.append(f"critical file missing from coverage report: {filename}")
            continue
        if not isinstance(floors, dict):
            failures.append(f"coverage floors for {filename} must be a table")
            continue
        for metric, floor in floors.items():
            if metric not in summaries[filename]:
                failures.append(f"{filename}: unknown metric {metric!r}")
                continue
            observed = summaries[filename][metric]
            if observed < float(floor):
                failures.append(
                    f"{filename} {metric}: {observed:.2f}% is below {float(floor):.2f}%"
                )
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=ROOT / "coverage.toml")
    parser.add_argument(
        "--section",
        default=None,
        help="coverage.toml table holding this lane's floors; the root tables when omitted",
    )
    parser.add_argument(
        "--format",
        dest="report_format",
        choices=sorted(NORMALIZERS),
        default=LLVM_FORMAT,
        help="report producer: cargo-llvm-cov JSON (default) or coverage.py JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.config.open("rb") as handle:
        config = tomllib.load(handle)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    failures = enforce(
        config,
        report,
        ROOT,
        section=args.section,
        report_format=args.report_format,
    )
    label = args.section or "workspace"
    if failures:
        print(f"Coverage ratchet failed ({label}):", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print(f"Coverage ratchet passed ({label}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
