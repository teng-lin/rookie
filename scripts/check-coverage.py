#!/usr/bin/env python3
"""Enforce ratcheted workspace and critical-file LLVM coverage floors."""

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


def percentage(summary: dict[str, object], metric: str) -> float:
    value = summary.get(metric)
    if not isinstance(value, dict) or not isinstance(value.get("percent"), (int, float)):
        raise ValueError(f"coverage report omitted {metric}.percent")
    return float(value["percent"])


def normalized_repo_path(filename: str, root: Path) -> str | None:
    path = Path(filename)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def enforce(config: dict[str, object], report: dict[str, object], root: Path) -> list[str]:
    data = report.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        return ["coverage report must contain exactly one data object"]
    payload = data[0]
    totals = payload.get("totals")
    files = payload.get("files")
    if not isinstance(totals, dict) or not isinstance(files, list):
        return ["coverage report omitted totals or files"]

    failures: list[str] = []
    workspace = config.get("workspace", {})
    if not isinstance(workspace, dict):
        return ["coverage config [workspace] must be a table"]
    for metric, floor in workspace.items():
        observed = percentage(totals, metric)
        if observed < float(floor):
            failures.append(
                f"workspace {metric}: {observed:.2f}% is below {float(floor):.2f}%"
            )

    summaries: dict[str, dict[str, object]] = {}
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("filename"), str):
            continue
        repo_path = normalized_repo_path(entry["filename"], root)
        summary = entry.get("summary")
        if repo_path is not None and isinstance(summary, dict):
            summaries[repo_path] = summary

    configured_files = config.get("files", {})
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
            observed = percentage(summaries[filename], metric)
            if observed < float(floor):
                failures.append(
                    f"{filename} {metric}: {observed:.2f}% is below {float(floor):.2f}%"
                )
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=ROOT / "coverage.toml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.config.open("rb") as handle:
        config = tomllib.load(handle)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    failures = enforce(config, report, ROOT)
    if failures:
        print("Coverage ratchet failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("Coverage ratchet passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
