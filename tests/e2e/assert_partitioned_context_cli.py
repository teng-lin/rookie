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
from cookie_manifest import ManifestError


class CliHeaderError(RuntimeError):
    def __init__(
        self,
        message: str,
        code: str | None = None,
        required: list[str] | None = None,
    ):
        super().__init__(message)
        self.code = code
        # The selector tokens the call is missing. The CLI defines `required`
        # for exactly `incomplete_send_context` and `isolation_loss_refused`,
        # drawing on the same vocabulary the Python and Node bindings expose,
        # so a caller that already branches on one binding's `required` reads
        # this one unchanged. `None` for every other code.
        self.required = required


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

    def command_for(self, subcommand: str, context: dict[str, Any]) -> list[str]:
        """Flatten a manifest send context onto the shared selector flags.

        `header` and `send-view` take the same `SendContextArgs`, so one
        mapping serves both and the two subcommands cannot be asked slightly
        different questions.
        """

        command = [
            str(self.cli),
            subcommand,
            "--browser",
            self.browser,
            "--profile",
            self.profile,
            "--url",
            str(context["url"]),
        ]
        for key, flag in (
            ("top_level_site", "--top-level-site"),
            ("resource", "--resource"),
            ("method", "--method"),
            ("user_context_id", "--user-context-id"),
            ("private_browsing_id", "--private-browsing-id"),
            ("first_party_domain", "--first-party-domain"),
            ("gecko_view_session_context_id", "--gecko-view-session-context-id"),
            ("origin_attributes", "--origin-attributes"),
        ):
            if context.get(key) is not None:
                command.extend([flag, str(context[key])])
        if context.get("ancestor_chain") is not None:
            # The CLI spells the two values in kebab-case; every other surface
            # uses the snake_case manifest spelling.
            command.extend(
                ["--ancestor-chain", str(context["ancestor_chain"]).replace("_", "-")]
            )
        return command

    def send_view(self, context: dict[str, Any]) -> dict[str, Any]:
        completed = self.run(self.command_for("send-view", context))
        document = json.loads(completed)
        if not isinstance(document, dict) or set(document) != {
            "cookies",
            "header",
            "omitted",
        }:
            raise CliHeaderError(
                f"send-view emitted an unexpected object shape: {sorted(document)!r}"
                if isinstance(document, dict)
                else f"send-view emitted {type(document).__name__}, expected an object"
            )
        return document

    def header(self, context: dict[str, Any]) -> str:
        return self.run(self.command_for("header", context)).strip()

    def run(self, command: list[str]) -> str:
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
            required = None
            for line in reversed(details.splitlines()):
                try:
                    error = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(error, dict) and isinstance(error.get("code"), str):
                    code = error["code"]
                    # An error object always carries `code` and `message`; a
                    # code may add documented fields, and unknown keys are
                    # ignored rather than rejected, so `required` is read
                    # only when the code defines it.
                    tokens = error.get("required")
                    if isinstance(tokens, list) and all(
                        isinstance(token, str) for token in tokens
                    ):
                        required = tokens
                    break
            if code == "incomplete_send_context" and not required:
                raise CliHeaderError(
                    f"incomplete_send_context must name the selectors it needs: {details}",
                    code,
                )
            raise CliHeaderError(details, code, required)
        return completed.stdout


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
    parser.add_argument("--nested-origin", required=True)
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
            nested_origin=args.nested_origin,
            expected_source_port=args.source_port,
            raw_manifest=(
                Path(os.environ["ROOKIE_E2E_CONTEXT_MANIFEST"])
                if os.environ.get("ROOKIE_E2E_CONTEXT_MANIFEST")
                else None
            ),
        )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    except (
        ContextAssertionError,
        CliHeaderError,
        ManifestError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"CLI partition context assertion failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
