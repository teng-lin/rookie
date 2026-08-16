#!/usr/bin/env python3
"""Gate `cargo audit` on structured, expiring exceptions.

Every RustSec advisory `cargo audit` reports against the committed
`Cargo.lock` must have a matching entry in `security/audit-exceptions.toml`
that carries an owner, a rationale, and an ISO-8601 expiry date that has not
passed. An advisory with no matching, unexpired entry fails the check; so
does a malformed or expired entry, even if it currently matches an advisory.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as error:
    raise SystemExit("check-audit-exceptions.py requires Python 3.11 or newer") from error


ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS_PATH = ROOT / "security" / "audit-exceptions.toml"
ADVISORY_ID_PATTERN = re.compile(r"^RUSTSEC-[0-9]{4}-[0-9]{4,}$")


def load_exceptions(path: Path) -> list[dict[str, Any]]:
    with path.open("rb") as handle:
        document = tomllib.load(handle)
    return document.get("exception", [])


def validate_exceptions(exceptions: list[dict[str, Any]], today: date) -> dict[str, date]:
    failures: list[str] = []
    valid: dict[str, date] = {}
    seen_ids: set[str] = set()
    for entry in exceptions:
        entry_id = entry.get("id")
        label = entry_id if isinstance(entry_id, str) else repr(entry)

        if not isinstance(entry_id, str) or not ADVISORY_ID_PATTERN.fullmatch(entry_id):
            failures.append(f"{label}: id must match {ADVISORY_ID_PATTERN.pattern}")
            continue
        if entry_id in seen_ids:
            failures.append(f"{entry_id}: duplicate exception entry")
            continue
        seen_ids.add(entry_id)

        owner = entry.get("owner")
        if not isinstance(owner, str) or not owner.strip():
            failures.append(f"{entry_id}: owner is required")

        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            failures.append(f"{entry_id}: rationale is required")

        expires = entry.get("expires")
        expiry_date: date | None = None
        if not isinstance(expires, str):
            failures.append(f"{entry_id}: expires is required (ISO-8601 date)")
        else:
            try:
                expiry_date = date.fromisoformat(expires)
            except ValueError:
                failures.append(f"{entry_id}: expires {expires!r} is not a valid ISO-8601 date")

        if expiry_date is not None:
            if expiry_date < today:
                failures.append(f"{entry_id}: exception expired on {expiry_date.isoformat()}")
            else:
                valid[entry_id] = expiry_date

    if failures:
        print("Audit exceptions are invalid:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)

    return valid


def run_cargo_audit() -> dict[str, Any]:
    result = subprocess.run(
        ["cargo", "audit", "--json"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    # `cargo audit` exits non-zero when it finds vulnerabilities; its JSON
    # report is still written to stdout in that case, so parse it either way.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"cargo audit did not produce valid JSON: {error}") from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exceptions",
        type=Path,
        default=EXCEPTIONS_PATH,
        help="path to the audit-exceptions.toml file (default: security/audit-exceptions.toml)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="read a pre-generated `cargo audit --json` report instead of running cargo audit",
    )
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=None,
        help="override today's date (ISO-8601) for expiry checks; for tests",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    today = args.today or date.today()
    valid_exceptions = validate_exceptions(load_exceptions(args.exceptions), today)

    report = (
        json.loads(args.report.read_text(encoding="utf-8")) if args.report else run_cargo_audit()
    )
    vulnerabilities = report.get("vulnerabilities", {}).get("list", [])
    found_ids = {vulnerability["advisory"]["id"] for vulnerability in vulnerabilities}

    uncovered = sorted(found_ids - valid_exceptions.keys())
    if uncovered:
        print(
            f"cargo audit found advisories with no matching, unexpired exception in {args.exceptions}:",
            file=sys.stderr,
        )
        for advisory_id in uncovered:
            print(f"- {advisory_id}", file=sys.stderr)
        return 1

    unused = sorted(valid_exceptions.keys() - found_ids)
    for advisory_id in unused:
        print(
            f"note: exception for {advisory_id} no longer matches any reported advisory; "
            "consider removing it",
            file=sys.stderr,
        )

    print(f"cargo audit: {len(found_ids)} advisories reported, all covered by exceptions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
