#!/usr/bin/env python3
"""Authenticated preflight: prove every live release control before any mutation.

R0's controls (the `release` environment's settings, the two `v*` tag
rulesets, and the required CI checks) live outside this repository's
checked-in files, as GitHub repository configuration. A publish workflow
that only trusts "we configured this once" has no way to notice the settings
drifting — an environment edited by hand, a ruleset deleted, a check renamed.
This script re-verifies all of it, live, via the GitHub API, immediately
before any publish workflow's first mutating step. It fails closed: any
unexpected state is a failure, not a warning.

Requires the `gh` CLI, authenticated (`GH_TOKEN`/`GITHUB_TOKEN` in the
environment — already true inside GitHub Actions), and a job permission of
at least `administration: read` to read environment and ruleset
configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from typing import Any


COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_ENVIRONMENT = "release"
REQUIRED_DEPLOYMENT_REFS = {("main", "branch"), ("v*", "tag")}

REQUIRED_TAG_RULESETS = {
    "release-tag-creation": {
        "rule_types": {"creation"},
        # (actor_id, actor_type) pairs, not bare ids: GitHub's bypass actor
        # ids are only unique *within* an actor_type, so checking id alone
        # would accept e.g. a Team or Integration that happens to share id 5
        # with the RepositoryRole "Admin" this is actually meant to allow.
        "bypass_actors": {(5, "RepositoryRole")},
    },
    "release-tag-immutable": {
        "rule_types": {"deletion", "update"},
        "bypass_actors": set(),
    },
}

# Check-run names, as GitHub Actions renders them for the release commit,
# that must have concluded "success". Kept in one place so every publish
# workflow checks the identical set. Confirmed against a real commit's
# check-runs API response, not guessed from workflow YAML — reusable
# workflows (`workflow_call`) render as "<caller job name> / <callee job
# name>", not the caller name alone. Artifact smoke is not a pull-request
# job; the per-commit-on-main signal is `artifact-smoke.yml`'s push-triggered
# jobs — same reusable `_artifact-smoke.yml`, always runs on push to main
# regardless of which paths changed. Chrome/Firefox e2e is likewise
# main/nightly/manual (`e2e.yml`), not pull_request.
_ARTIFACT_SMOKE_SUB_JOBS = (
    "Build release packages",
    "Install and exercise downloaded packages (Node.js 22)",
    "Install and exercise downloaded packages (Node.js 24)",
    "Install and exercise downloaded packages (Node.js 26)",
)
_ARTIFACT_SMOKE_PLATFORMS = ("Ubuntu x64 packages", "Windows x64 packages", "macOS ARM64 packages")
_FULL_RELEASE_GATES = (
    "release gate: full test suite",
    "release gate: real browsers",
    "release gate: claimed browsers",
    "release gate: installed artifacts",
    "release gate: assurance",
    "release gate: security",
)

REQUIRED_CHECK_RUNS = (
    "e2e ubuntu × chrome (libsecret)",
    "e2e ubuntu × firefox",
    "e2e macos × firefox",
    "e2e macos × chrome (real Keychain lookup)",
    "e2e windows × firefox",
    "e2e windows × chrome (App-Bound v20 staged-WAL recovery + liveness)",
    "e2e windows × chrome (legacy DPAPI)",
    *(f"{platform} / {sub_job}" for platform in _ARTIFACT_SMOKE_PLATFORMS for sub_job in _ARTIFACT_SMOKE_SUB_JOBS),
    "check (ubuntu-latest)",
    *_FULL_RELEASE_GATES,
)


class ControlFailure(Exception):
    pass


def gh_api(path: str, *, repo: str) -> Any:
    # encoding="utf-8" is required: on Windows the default locale encoding is
    # often cp1252, which corrupts check-run names containing "×" (and any
    # other non-ASCII) in the JSON body and makes required-check matching
    # fail closed with "no check run found".
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/{path}", "-H", "Accept: application/vnd.github+json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise ControlFailure(f"GitHub API request failed for {path!r}: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ControlFailure(f"GitHub API response for {path!r} was not valid JSON: {error}") from error


def check_release_environment(repo: str) -> list[str]:
    failures: list[str] = []
    environment = gh_api(f"environments/{REQUIRED_ENVIRONMENT}", repo=repo)

    if environment.get("can_admins_bypass") is not False:
        failures.append(
            f"environment {REQUIRED_ENVIRONMENT!r}: can_admins_bypass must be false, "
            f"got {environment.get('can_admins_bypass')!r}"
        )

    policy = environment.get("deployment_branch_policy") or {}
    if not policy.get("custom_branch_policies"):
        failures.append(
            f"environment {REQUIRED_ENVIRONMENT!r}: deployment_branch_policy must use "
            "custom_branch_policies, so only explicitly listed refs may deploy"
        )
        return failures

    policies = gh_api(f"environments/{REQUIRED_ENVIRONMENT}/deployment-branch-policies", repo=repo)
    actual_refs = {
        (entry["name"], entry["type"]) for entry in policies.get("branch_policies", [])
    }
    if actual_refs != REQUIRED_DEPLOYMENT_REFS:
        failures.append(
            f"environment {REQUIRED_ENVIRONMENT!r}: deployment refs are {sorted(actual_refs)}, "
            f"expected exactly {sorted(REQUIRED_DEPLOYMENT_REFS)}"
        )

    return failures


def check_tag_rulesets(repo: str) -> list[str]:
    failures: list[str] = []
    rulesets = gh_api("rulesets", repo=repo)
    by_name = {entry["name"]: entry for entry in rulesets}

    for name, expectation in REQUIRED_TAG_RULESETS.items():
        summary = by_name.get(name)
        if summary is None:
            failures.append(f"tag ruleset {name!r}: missing")
            continue

        ruleset = gh_api(f"rulesets/{summary['id']}", repo=repo)

        if ruleset.get("target") != "tag":
            failures.append(f"tag ruleset {name!r}: target must be 'tag'")
        if ruleset.get("enforcement") != "active":
            failures.append(
                f"tag ruleset {name!r}: enforcement must be 'active', got {ruleset.get('enforcement')!r}"
            )

        include = set(ruleset.get("conditions", {}).get("ref_name", {}).get("include", []))
        if include != {"refs/tags/v*"}:
            failures.append(
                f"tag ruleset {name!r}: ref_name include must be exactly refs/tags/v*, got {sorted(include)}"
            )

        rule_types = {rule["type"] for rule in ruleset.get("rules", [])}
        if rule_types != expectation["rule_types"]:
            failures.append(
                f"tag ruleset {name!r}: rule types are {sorted(rule_types)}, "
                f"expected exactly {sorted(expectation['rule_types'])}"
            )

        bypass_actors = {
            (actor["actor_id"], actor["actor_type"]) for actor in ruleset.get("bypass_actors", [])
        }
        # In GitHub Actions under GITHUB_TOKEN (non-admin), GitHub redacts the
        # bypass_actors list to [] for rulesets where the token cannot bypass.
        # If bypass_actors is returned non-empty, or expectation is empty (no bypass
        # allowed), verify exact match.
        if bypass_actors or not expectation["bypass_actors"]:
            if bypass_actors != expectation["bypass_actors"]:
                failures.append(
                    f"tag ruleset {name!r}: bypass actors are {sorted(bypass_actors)}, "
                    f"expected exactly {sorted(expectation['bypass_actors'])}"
                )

    return failures


def fetch_all_check_runs(
    repo: str,
    commit_sha: str,
    *,
    api: Any | None = None,
) -> list[dict[str, Any]]:
    """Return every check-run for ``commit_sha``, paging past GitHub's 100-item cap.

    ``commits/{sha}/check-runs`` defaults to ``per_page=30`` and caps at 100.
    A busy release commit routinely exceeds that (publish retries, cancelled
    matrix legs, lint/test/e2e/smoke), so a single-page fetch can miss a
    required check that still exists — the failure mode that blocked
    ``publish-cli.yml`` for ``v0.6.0-beta.1`` after earlier registry publishes
    had already passed against a shorter check-run list.

    ``api`` defaults to this module's ``gh_api``. Callers that re-export
    ``gh_api`` for test patching (``write-ci-proof.py``) should pass their
    local alias so patches still apply.
    """
    request = api if api is not None else gh_api
    page = 1
    collected: list[dict[str, Any]] = []
    total_count: int | None = None
    while True:
        response = request(
            f"commits/{commit_sha}/check-runs?per_page=100&page={page}",
            repo=repo,
        )
        if total_count is None:
            raw_total = response.get("total_count")
            total_count = raw_total if isinstance(raw_total, int) else None
        runs = response.get("check_runs") or []
        if not isinstance(runs, list):
            raise ControlFailure(
                f"commits/{commit_sha}/check-runs page {page}: expected check_runs list, "
                f"got {type(runs).__name__}"
            )
        collected.extend(runs)
        if not runs:
            break
        if total_count is not None and len(collected) >= total_count:
            break
        if len(runs) < 100:
            break
        page += 1
    return collected


def select_latest_check_run(name: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the newest real execution, rejecting runs that cannot be ordered."""
    executed = [run for run in runs if run.get("conclusion") != "skipped"]
    candidates = executed or runs
    ordered: list[tuple[datetime, dict[str, Any]]] = []
    for run in candidates:
        started_at = run.get("started_at")
        if not isinstance(started_at, str) or not started_at:
            raise ControlFailure(
                f"required check {name!r}: cannot order check run {run.get('id')!r}; "
                "started_at is missing"
            )
        try:
            timestamp = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ControlFailure(
                f"required check {name!r}: cannot order check run {run.get('id')!r}; "
                f"started_at is invalid: {started_at!r}"
            ) from error
        if timestamp.tzinfo is None:
            raise ControlFailure(
                f"required check {name!r}: cannot order check run {run.get('id')!r}; "
                f"started_at has no timezone: {started_at!r}"
            )
        ordered.append((timestamp, run))
    return max(ordered, key=lambda entry: entry[0])[1]


def check_required_checks(repo: str, commit_sha: str) -> list[str]:
    failures: list[str] = []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for run in fetch_all_check_runs(repo, commit_sha):
        by_name.setdefault(run["name"], []).append(run)

    for name in REQUIRED_CHECK_RUNS:
        runs = by_name.get(name)
        if not runs:
            failures.append(f"required check {name!r}: no check run found for {commit_sha}")
            continue
        # A commit can carry more than one run of the same name. A tag push can
        # create a newer, intentionally skipped copy of a dispatch-only release
        # gate; that non-execution must not mask the successful manual gate.
        # Among runs that actually execute, the newest still governs so a later
        # pending or failed rerun keeps publication fail-closed.
        try:
            latest = select_latest_check_run(name, runs)
        except ControlFailure as error:
            failures.append(str(error))
            continue
        if latest.get("status") != "completed":
            failures.append(f"required check {name!r}: not completed (status={latest.get('status')!r})")
        elif latest.get("conclusion") != "success":
            failures.append(
                f"required check {name!r}: conclusion is {latest.get('conclusion')!r}, not success"
            )

    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="owner/repo (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--commit-sha",
        required=True,
        help="the verified release commit (40-hex) to check required checks against",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.repo:
        print("error: --repo not given and $GITHUB_REPOSITORY is not set", file=sys.stderr)
        return 1
    if not COMMIT_PATTERN.fullmatch(args.commit_sha):
        print(f"error: --commit-sha must be a lowercase 40-character commit SHA, got {args.commit_sha!r}", file=sys.stderr)
        return 1

    failures: list[str] = []
    try:
        failures.extend(check_release_environment(args.repo))
        failures.extend(check_tag_rulesets(args.repo))
        failures.extend(check_required_checks(args.repo, args.commit_sha))
    except ControlFailure as error:
        print(f"release controls preflight could not complete: {error}", file=sys.stderr)
        return 1

    if failures:
        print("Release controls preflight failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Release controls preflight passed for {args.repo}@{args.commit_sha}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
