#!/usr/bin/env python3
"""Run one extraction surface concurrently and verify every exact result.

The command after ``--`` must print a JSON cookie array. The caller chooses a
flat or detailed manifest projection. This runner performs no browser
discovery itself; CI passes commands that target one explicitly disposable
profile database.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import sys
import time
from typing import Sequence

from cookie_manifest import ManifestError, load_manifest, verify_records


class StressError(RuntimeError):
    """A concurrent extraction failed or violated the exact manifest."""


def run_once(
    command: Sequence[str],
    *,
    timeout: float,
    manifest: dict,
    projection: str,
    surface: str,
    ordinal: int,
) -> int:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise StressError(f"{surface}[{ordinal}] could not complete: {error}") from error
    if completed.returncode != 0:
        raise StressError(
            f"{surface}[{ordinal}] exited {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip() or '<no output>'}"
        )
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise StressError(
            f"{surface}[{ordinal}] did not emit JSON: {completed.stdout!r}"
        ) from error
    try:
        return verify_records(
            manifest,
            projection,
            records,
            surface=f"{surface}[{ordinal}]",
        )
    except ManifestError as error:
        raise StressError(str(error)) from error


def run_stress(
    command: Sequence[str],
    *,
    timeout: float,
    manifest: dict,
    projection: str,
    surface: str,
    workers: int,
    iterations: int,
) -> dict[str, int | float | str]:
    if not command:
        raise StressError("an extraction command is required after --")
    if workers < 1 or iterations < 1:
        raise StressError("workers and iterations must be positive")
    total = workers * iterations
    started = time.monotonic()
    counts: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                run_once,
                command,
                timeout=timeout,
                manifest=manifest,
                projection=projection,
                surface=surface,
                ordinal=ordinal,
            )
            for ordinal in range(total)
        ]
        try:
            for future in as_completed(futures):
                counts.append(future.result())
        except Exception:
            for future in futures:
                future.cancel()
            raise
    unique_counts = set(counts)
    if len(unique_counts) != 1:
        raise StressError(f"concurrent runs disagreed on row counts: {sorted(unique_counts)}")
    return {
        "surface": surface,
        "projection": projection,
        "workers": workers,
        "iterations": iterations,
        "runs": total,
        "rows_per_run": counts[0],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--projection",
        choices=("filtered_flat", "unfiltered_flat", "detailed"),
        required=True,
    )
    parser.add_argument("--surface", required=True)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        manifest = load_manifest(args.manifest)
        result = run_stress(
            command,
            timeout=args.timeout,
            manifest=manifest,
            projection=args.projection,
            surface=args.surface,
            workers=args.workers,
            iterations=args.iterations,
        )
        print(json.dumps(result, sort_keys=True))
    except (ManifestError, StressError, OSError) as error:
        print(f"cookie stress failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
