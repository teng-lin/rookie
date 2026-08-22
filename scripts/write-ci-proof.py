#!/usr/bin/env python3
"""Non-spoofable CI proof: verify required checks trace to genuine Actions runs.

Release-hardening program R5. `scripts/check-release-controls.py`'s
`check_required_checks` verifies a commit's required checks **purely by the
check-run `name` string** returned by `commits/{sha}/check-runs` -- it never
verifies which workflow file, run, event, or repository actually produced
that check-run. The GitHub Checks API lets any token/App with `checks:write`
on the repo create a check-run with an arbitrary name for an arbitrary
commit, so a name match alone cannot distinguish "the real job ran and
passed" from "something else posted a check-run happening to share that
name."

This script closes that gap for a given commit: for every required check
(the same `REQUIRED_CHECK_RUNS` list `check-release-controls.py` already
uses -- imported, not duplicated), it resolves the check-run to the exact
job and workflow run that produced it via `check_run.id == job.id` (GitHub's
own correlation key, not a self-reported field) and
`GET actions/jobs/{id}` -> `run_id` -> `GET actions/runs/{run_id}`, then
verifies the run's repository (not a fork), workflow file path (against an
explicit trusted-workflow allowlist), trigger event, and that both the run's
and the job's `head_sha` match the target commit exactly -- closing any
indirection tampering between the check-runs lookup and the resolved run.
Iterating every individually-named required check this way already proves
matrix-leg completeness: a silently skipped leg has no matching check-run,
or one that never reaches `status: completed`, either of which is a failure
here -- no separate `actions/runs/{id}/jobs` enumeration is needed on top of
that per-name loop.

It does **not** replace `check-release-controls.py`'s existing preflight --
that stays the fast, cheap first gate. This is additive, independent
verification, producing a `ci-proof.json` bound (via `manifest_digest`) to
one specific release manifest, RFC 8785 JCS-hashed so it reproduces
identically regardless of field order or host. "Attested" beyond that digest
-- real cryptographic signing (Sigstore/OIDC-based attestation) -- is
explicitly out of scope here, matching how PR 1's R3 already deferred full
attestation to a later phase; this script itself never mutates anything and
holds no publish authority of its own.

Wired into every publish workflow as a blocking gate immediately before the
registry or GitHub release mutation. Any missing, stale, or unverifiable
proof fails closed and prevents publication -- see docs/releasing.md.

Requires the `gh` CLI, authenticated, same as `check-release-controls.py`.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import jcs  # noqa: E402

_CONTROLS_SPEC = importlib.util.spec_from_file_location(
    "check_release_controls", ROOT / "check-release-controls.py"
)
assert _CONTROLS_SPEC is not None and _CONTROLS_SPEC.loader is not None
check_release_controls = importlib.util.module_from_spec(_CONTROLS_SPEC)
sys.modules[_CONTROLS_SPEC.name] = check_release_controls
_CONTROLS_SPEC.loader.exec_module(check_release_controls)

gh_api = check_release_controls.gh_api
ControlFailure = check_release_controls.ControlFailure
COMMIT_PATTERN = check_release_controls.COMMIT_PATTERN
REQUIRED_CHECK_RUNS = check_release_controls.REQUIRED_CHECK_RUNS
fetch_all_check_runs = check_release_controls.fetch_all_check_runs
select_latest_check_run = check_release_controls.select_latest_check_run
_ARTIFACT_SMOKE_SUB_JOBS = check_release_controls._ARTIFACT_SMOKE_SUB_JOBS
_ARTIFACT_SMOKE_PLATFORMS = check_release_controls._ARTIFACT_SMOKE_PLATFORMS

DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Every required check's producing workflow file, confirmed directly against
# the real workflow YAML (not guessed): the seven "e2e ..." names are
# e2e.yml's own top-level jobs; the twelve "{platform} / {sub_job}" names are
# artifact-smoke.yml's push-triggered jobs calling the reusable
# _artifact-smoke.yml (workflow_call renders as "<caller job> / <callee
# job>", and the run this resolves to is always the *caller's* run --
# reusable workflows execute inside the caller's run, not a separate one);
# "check (ubuntu-latest)" is test-rust.yml's combined Linux job (fmt,
# package, metadata, cargo-audit, clippy, tests, public API). The six
# "release gate: ..." sentinels are manual, exact-commit aggregations: each
# succeeds only after every lane in its full release-mode workflow succeeds.
_TRUSTED_WORKFLOW_FOR_CHECK: dict[str, str] = {
    "e2e ubuntu × chrome (libsecret)": ".github/workflows/e2e.yml",
    "e2e ubuntu × firefox": ".github/workflows/e2e.yml",
    "e2e macos × firefox": ".github/workflows/e2e.yml",
    "e2e macos × chrome (real Keychain lookup)": ".github/workflows/e2e.yml",
    "e2e windows × firefox": ".github/workflows/e2e.yml",
    "e2e windows × chrome (App-Bound v20 staged-WAL recovery + liveness)": ".github/workflows/e2e.yml",
    "e2e windows × chrome (legacy DPAPI)": ".github/workflows/e2e.yml",
    "check (ubuntu-latest)": ".github/workflows/test-rust.yml",
    "release gate: full test suite": ".github/workflows/test-rust.yml",
    "release gate: real browsers": ".github/workflows/e2e.yml",
    "release gate: claimed browsers": ".github/workflows/e2e-release.yml",
    "release gate: installed artifacts": ".github/workflows/artifact-smoke.yml",
    "release gate: assurance": ".github/workflows/assurance.yml",
    "release gate: security": ".github/workflows/security.yml",
}
for _platform in _ARTIFACT_SMOKE_PLATFORMS:
    for _sub_job in _ARTIFACT_SMOKE_SUB_JOBS:
        _TRUSTED_WORKFLOW_FOR_CHECK[f"{_platform} / {_sub_job}"] = ".github/workflows/artifact-smoke.yml"
assert set(_TRUSTED_WORKFLOW_FOR_CHECK) == set(REQUIRED_CHECK_RUNS), (
    "every REQUIRED_CHECK_RUNS name must have a trusted workflow mapping, and vice versa"
)

# The trusted workflows trigger on some combination of `push`, `schedule`, and
# `workflow_dispatch` (every full release gate is manual) -- rejecting those would
# produce false failures on a perfectly genuine run: `verify_required_checks`
# already picks the *most recently started* run for a given check name, so a
# Monday cron firing while a release commit sits at the tip of `main` would
# otherwise be rejected even though it re-ran (and re-passed) the exact same
# checks. `pull_request` is deliberately excluded: this repo squash-merges
# PRs, so a pull_request-triggered run's head_sha is the pre-merge branch
# commit, never the post-merge commit being verified here.
_TRUSTED_EVENTS = {"push", "schedule", "workflow_dispatch"}

# `workflow_dispatch` specifically can target a non-main ref (see
# e2e.yml's windows-chrome-appbound job comment: "maintainers may explicitly
# select a trusted feature ref for pre-merge validation with
# workflow_dispatch") -- head_sha pinning to the exact target commit already
# makes that hard to exploit (a feature-branch run's head_sha would need to
# collide with the release commit's own SHA), but head_branch is cheap,
# unconditional defense-in-depth rather than relying solely on that.
_TRUSTED_BRANCH = "main"


def verify_required_checks(repo: str, commit_sha: str) -> tuple[list[dict[str, Any]], list[str]]:
    verified: list[dict[str, Any]] = []
    failures: list[str] = []

    by_name: dict[str, list[dict[str, Any]]] = {}
    # Pass this module's gh_api alias so tests that patch write_ci_proof.gh_api
    # still intercept the check-runs fetches inside fetch_all_check_runs.
    for run in fetch_all_check_runs(repo, commit_sha, api=gh_api):
        by_name.setdefault(run["name"], []).append(run)

    for name in REQUIRED_CHECK_RUNS:
        runs = by_name.get(name)
        if not runs:
            failures.append(f"required check {name!r}: no check run found for {commit_sha}")
            continue
        try:
            latest = select_latest_check_run(name, runs)
        except ControlFailure as error:
            failures.append(str(error))
            continue
        if latest.get("status") != "completed":
            failures.append(f"required check {name!r}: not completed (status={latest.get('status')!r})")
            continue
        if latest.get("conclusion") != "success":
            failures.append(
                f"required check {name!r}: conclusion is {latest.get('conclusion')!r}, not success"
            )
            continue

        try:
            job = gh_api(f"actions/jobs/{latest['id']}", repo=repo)
        except ControlFailure as error:
            failures.append(f"required check {name!r}: could not resolve producing job: {error}")
            continue
        # check_run.id == job.id is documented as GitHub's own correlation
        # key, not a self-reported field -- but nothing structurally
        # guarantees that assumption stays true. Cross-checking the
        # resolved job's own name against the check-run's name makes it
        # self-verifying: if the ID spaces ever diverged, this catches it
        # immediately instead of silently trusting whatever job that ID
        # happened to resolve to.
        if job.get("name") != name:
            failures.append(
                f"required check {name!r}: resolved job {latest['id']} is named "
                f"{job.get('name')!r} -- check-run/job correlation is broken"
            )
            continue
        run_id = job.get("run_id")
        try:
            run = gh_api(f"actions/runs/{run_id}", repo=repo)
        except ControlFailure as error:
            failures.append(f"required check {name!r}: could not resolve producing run {run_id!r}: {error}")
            continue

        expected_path = _TRUSTED_WORKFLOW_FOR_CHECK[name]
        if run.get("path") != expected_path:
            failures.append(
                f"required check {name!r}: produced by workflow {run.get('path')!r}, "
                f"expected {expected_path!r}"
            )
            continue
        if run.get("event") not in _TRUSTED_EVENTS:
            failures.append(
                f"required check {name!r}: run event is {run.get('event')!r}, "
                f"expected one of {sorted(_TRUSTED_EVENTS)!r}"
            )
            continue
        if run.get("head_branch") != _TRUSTED_BRANCH:
            failures.append(
                f"required check {name!r}: run head_branch is {run.get('head_branch')!r}, "
                f"expected {_TRUSTED_BRANCH!r}"
            )
            continue
        if job.get("head_sha") != commit_sha or run.get("head_sha") != commit_sha:
            failures.append(
                f"required check {name!r}: job/run head_sha ({job.get('head_sha')!r}, "
                f"{run.get('head_sha')!r}) does not match {commit_sha}"
            )
            continue
        head_repository = (run.get("head_repository") or {}).get("full_name")
        if head_repository != repo:
            failures.append(
                f"required check {name!r}: run's head_repository is {head_repository!r}, "
                f"expected {repo!r} (not a fork)"
            )
            continue
        if run.get("conclusion") != "success":
            failures.append(
                f"required check {name!r}: run conclusion is {run.get('conclusion')!r}, not success"
            )
            continue

        verified.append(
            {
                "name": name,
                "run_id": run_id,
                "workflow_path": run.get("path"),
                "event": run.get("event"),
                "conclusion": run.get("conclusion"),
                "run_attempt": job.get("run_attempt"),
            }
        )

    return verified, failures


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
        help="the release commit (40-hex) to verify required checks against",
    )
    digest_source = parser.add_mutually_exclusive_group(required=True)
    digest_source.add_argument(
        "--manifest-digest",
        help="release.manifest_digest from write-release-scan-manifest.py -- what this proof is bound to",
    )
    digest_source.add_argument(
        "--manifest",
        type=Path,
        help="path to a release-scan-manifest.json to read release.manifest_digest from directly",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def _resolve_manifest_digest(args: argparse.Namespace) -> tuple[str | None, str | None]:
    """Returns `(digest, problem)` -- exactly one is `None`."""
    if args.manifest_digest is not None:
        return args.manifest_digest, None
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        release = manifest["release"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        return None, f"could not read release.manifest_digest from {args.manifest}: {error}"
    if not isinstance(release, dict):
        return None, f"{args.manifest}: release is not an object (got {release!r})"
    try:
        digest = release["manifest_digest"]
    except KeyError as error:
        return None, f"could not read release.manifest_digest from {args.manifest}: {error}"
    if not isinstance(digest, str):
        return None, f"{args.manifest}: release.manifest_digest is not a string (got {digest!r})"
    actual_digest = jcs.digest(
        {
            "release": {key: value for key, value in release.items() if key != "manifest_digest"},
            "artifacts": manifest.get("artifacts", []),
        }
    )
    if digest != actual_digest:
        return (
            None,
            f"{args.manifest}: release.manifest_digest {digest!r} does not match "
            f"the manifest's actual content (recomputed {actual_digest!r})",
        )
    return digest, None


def _report_failure(problems: list[str]) -> int:
    summary = "CI proof verification failed:\n" + "\n".join(f"- {problem}" for problem in problems)
    print(summary, file=sys.stderr)
    return 1


def main() -> int:
    args = parse_args()
    problems: list[str] = []

    if not args.repo:
        problems.append("--repo not given and $GITHUB_REPOSITORY is not set")
    if not COMMIT_PATTERN.fullmatch(args.commit_sha):
        problems.append(f"--commit-sha must be a lowercase 40-character commit SHA, got {args.commit_sha!r}")

    manifest_digest: str | None = None
    verified: list[dict[str, Any]] = []
    if not problems:
        try:
            manifest_digest, digest_problem = _resolve_manifest_digest(args)
            if digest_problem is not None:
                problems.append(digest_problem)
            elif not DIGEST_PATTERN.fullmatch(manifest_digest):
                problems.append(
                    f"manifest digest must be a lowercase 64-character SHA-256 hex digest, got {manifest_digest!r}"
                )

            if not problems:
                verified, verification_failures = verify_required_checks(args.repo, args.commit_sha)
                problems.extend(verification_failures)
        except ControlFailure as error:
            problems.append(f"CI proof could not be produced: {error}")
        except Exception as error:  # noqa: BLE001
            # Keep failures actionable and fail closed even for malformed API
            # responses or unexpected manifest bytes, rather than leaking an
            # unstructured traceback from a release gate.
            problems.append(f"CI proof could not be produced due to an unexpected error: {error!r}")

    if problems:
        return _report_failure(problems)

    proof = {
        "schema_version": 1,
        "manifest_digest": manifest_digest,
        "commit_sha": args.commit_sha,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "checks": sorted(verified, key=lambda check: check["name"]),
    }
    proof["proof_digest"] = jcs.digest(proof)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    print(f"CI proof written for {args.repo}@{args.commit_sha}, bound to manifest digest {manifest_digest}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
