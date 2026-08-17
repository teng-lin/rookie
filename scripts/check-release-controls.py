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
# name>", not the caller name alone, and `e2e.yml`'s `artifact-pr-*` jobs are
# explicitly PR-only (`if: github.event_name == 'pull_request'`); the
# per-commit-on-main signal is `artifact-smoke.yml`'s push-triggered jobs
# instead — same reusable `_artifact-smoke.yml`, different caller, always
# runs on push to main regardless of which paths changed.
_ARTIFACT_SMOKE_SUB_JOBS = (
    "Build release packages",
    "Install and exercise downloaded packages (Node.js 22)",
    "Install and exercise downloaded packages (Node.js 24)",
    "Install and exercise downloaded packages (Node.js 26)",
)
_ARTIFACT_SMOKE_PLATFORMS = ("Ubuntu x64 packages", "Windows x64 packages", "macOS ARM64 packages")

REQUIRED_CHECK_RUNS = (
    "e2e ubuntu × chrome (libsecret)",
    "e2e ubuntu × firefox",
    "e2e macos × firefox",
    "e2e macos × chrome (real Keychain lookup)",
    "e2e windows × firefox",
    "e2e windows × chrome (App-Bound v20 canary)",
    "e2e windows × chrome (legacy DPAPI)",
    *(f"{platform} / {sub_job}" for platform in _ARTIFACT_SMOKE_PLATFORMS for sub_job in _ARTIFACT_SMOKE_SUB_JOBS),
    "cargo audit (blocking)",
)


class ControlFailure(Exception):
    pass


def gh_api(path: str, *, repo: str) -> Any:
    result = subprocess.run(
        ["gh", "api", f"repos/{repo}/{path}", "-H", "Accept: application/vnd.github+json"],
        capture_output=True,
        text=True,
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


def check_required_checks(repo: str, commit_sha: str) -> list[str]:
    failures: list[str] = []
    response = gh_api(f"commits/{commit_sha}/check-runs?per_page=100", repo=repo)
    by_name: dict[str, list[dict[str, Any]]] = {}
    for run in response.get("check_runs", []):
        by_name.setdefault(run["name"], []).append(run)

    for name in REQUIRED_CHECK_RUNS:
        runs = by_name.get(name)
        if not runs:
            failures.append(f"required check {name!r}: no check run found for {commit_sha}")
            continue
        # A commit can carry more than one run of the same name (reruns); the
        # most recently started run is the one that governs.
        latest = max(runs, key=lambda run: run.get("started_at") or "")
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
