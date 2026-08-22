#!/usr/bin/env python3
"""Assert partitioned detailed output and header isolation through the CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from assert_partitioned_context import ContextAssertionError, validate_context_snapshot


class CliHeaderError(RuntimeError):
    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


class CliSnapshot:
    def __init__(
        self,
        records: list[dict[str, Any]],
        *,
        cli: Path,
        browser: str,
        profile: str,
        environment: dict[str, str],
    ) -> None:
        self.records = records
        self.cli = cli
        self.browser = browser
        self.profile = profile
        self.environment = environment

    def detailed_cookies(self) -> list[dict[str, Any]]:
        return self.records

    def header(self, context: dict[str, Any]) -> str:
        command = [
            str(self.cli),
            "header",
            "--browser",
            self.browser,
            "--profile",
            self.profile,
            "--url",
            str(context["url"]),
        ]
        if context.get("top_level_site") is not None:
            command.extend(["--top-level-site", str(context["top_level_site"])])
        if context.get("resource") is not None:
            command.extend(["--resource", str(context["resource"])])
        if context.get("method") is not None:
            command.extend(["--method", str(context["method"])])
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=self.environment,
        )
        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip()
            code = None
            for line in reversed(details.splitlines()):
                try:
                    error = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(error, dict) and isinstance(error.get("code"), str):
                    code = error["code"]
                    break
            raise CliHeaderError(details, code)
        return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("chromium", "firefox"), required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--browser-id", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--top-origin", required=True)
    parser.add_argument("--other-top-origin", required=True)
    parser.add_argument("--third-origin", required=True)
    parser.add_argument("--source-port", type=int, required=True)
    args = parser.parse_args()

    command = [
        str(args.cli),
        "from-path",
        str(args.database),
        "--format",
        "detailed",
    ]
    if args.engine == "chromium":
        command.extend(["--browser-id", args.browser_id])
    environment = os.environ.copy()
    environment["RUST_LOG"] = "error"
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=environment,
        )
        records = json.loads(completed.stdout)
        if not isinstance(records, list):
            raise ContextAssertionError("CLI detailed output was not an array")
        snapshot = CliSnapshot(
            records,
            cli=args.cli,
            browser=args.browser_id,
            profile=args.profile_id,
            environment=environment,
        )
        result = validate_context_snapshot(
            snapshot,
            engine=args.engine,
            top_origin=args.top_origin,
            other_top_origin=args.other_top_origin,
            third_origin=args.third_origin,
            expected_source_port=args.source_port,
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except (
        ContextAssertionError,
        CliHeaderError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"CLI partition context assertion failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
