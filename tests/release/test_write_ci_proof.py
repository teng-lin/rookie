from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "write_ci_proof", REPOSITORY_ROOT / "scripts/write-ci-proof.py"
)
assert SPEC is not None and SPEC.loader is not None
write_ci_proof = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = write_ci_proof
SPEC.loader.exec_module(write_ci_proof)

JCS_SPEC = importlib.util.spec_from_file_location("jcs", REPOSITORY_ROOT / "scripts/jcs.py")
assert JCS_SPEC is not None and JCS_SPEC.loader is not None
jcs = importlib.util.module_from_spec(JCS_SPEC)
sys.modules[JCS_SPEC.name] = jcs
JCS_SPEC.loader.exec_module(jcs)

REPO = "teng-lin/rookie-cookies"
COMMIT_SHA = "a" * 40
MANIFEST_DIGEST = "d" * 64


def build_good_fixture(
    repo: str, commit_sha: str
) -> tuple[dict[str, object], dict[int, dict[str, object]], dict[int, dict[str, object]]]:
    """A fully genuine pass for every REQUIRED_CHECK_RUNS entry: all checks
    named `"{platform} / {sub_job}"` share one artifact-smoke.yml run (that's
    really how they're produced), all seven `"e2e ..."` checks share one
    e2e.yml run, and `"check (ubuntu-latest)"` gets its own test-rust.yml
    run -- mirroring the real repo's actual run topology, not one run per
    check."""
    check_runs: list[dict[str, object]] = []
    jobs_by_id: dict[int, dict[str, object]] = {}
    runs_by_id: dict[int, dict[str, object]] = {}
    run_id_by_path: dict[str, int] = {}
    next_run_id = 1000

    for index, name in enumerate(write_ci_proof.REQUIRED_CHECK_RUNS):
        check_id = 100 + index
        path = write_ci_proof._TRUSTED_WORKFLOW_FOR_CHECK[name]
        if path not in run_id_by_path:
            run_id_by_path[path] = next_run_id
            next_run_id += 1
        run_id = run_id_by_path[path]

        check_runs.append(
            {
                "id": check_id,
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-01-01T00:00:00Z",
            }
        )
        jobs_by_id[check_id] = {
            "run_id": run_id,
            "head_sha": commit_sha,
            "run_attempt": 1,
            "name": name,
        }
        runs_by_id[run_id] = {
            "path": path,
            "event": "push",
            "head_sha": commit_sha,
            "head_branch": "main",
            "conclusion": "success",
            "head_repository": {"full_name": repo},
        }

    return {"check_runs": check_runs}, jobs_by_id, runs_by_id


def fake_gh_api_for(
    check_runs_response: dict[str, object],
    jobs_by_id: dict[int, dict[str, object]],
    runs_by_id: dict[int, dict[str, object]],
    *,
    commit_sha: str,
):
    def fake_gh_api(path: str, *, repo: str):
        if path == f"commits/{commit_sha}/check-runs?per_page=100&page=1":
            return check_runs_response
        if path.startswith("actions/jobs/"):
            return jobs_by_id[int(path.removeprefix("actions/jobs/"))]
        if path.startswith("actions/runs/"):
            return runs_by_id[int(path.removeprefix("actions/runs/"))]
        raise AssertionError(f"unexpected gh_api call: {path}")

    return fake_gh_api


class VerifyRequiredChecksTests(unittest.TestCase):
    def test_genuine_pass_verifies_every_required_check(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertEqual(failures, [])
        self.assertEqual({check["name"] for check in verified}, set(write_ci_proof.REQUIRED_CHECK_RUNS))
        for check in verified:
            self.assertEqual(check["event"], "push")
            self.assertEqual(check["conclusion"], "success")

    def test_missing_check_run_fails(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        check_runs["check_runs"] = [
            entry for entry in check_runs["check_runs"] if entry["name"] != "check (ubuntu-latest)"
        ]
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("check (ubuntu-latest)" in failure and "no check run found" in failure for failure in failures))
        self.assertNotIn("check (ubuntu-latest)", {check["name"] for check in verified})

    def test_a_check_run_pointing_at_the_wrong_workflow_fails(self) -> None:
        # A forged check-run: right name, right commit, right conclusion --
        # but its resolved run comes from a workflow this check is not
        # trusted to be produced by. A name match alone (what
        # check-release-controls.py checks) would have accepted this.
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        target_run_id = jobs[100]["run_id"]  # first REQUIRED_CHECK_RUNS entry
        runs[target_run_id]["path"] = ".github/workflows/not-trusted.yml"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("produced by workflow" in failure for failure in failures))
        first_name = write_ci_proof.REQUIRED_CHECK_RUNS[0]
        self.assertNotIn(first_name, {check["name"] for check in verified})

    def test_a_pull_request_triggered_run_is_rejected(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        target_run_id = jobs[100]["run_id"]
        runs[target_run_id]["event"] = "pull_request"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("run event is" in failure for failure in failures))

    def test_a_genuine_schedule_triggered_run_is_accepted(self) -> None:
        # A cron re-run of the same checks (artifact-smoke.yml/e2e.yml both
        # have a Monday schedule) is exactly as trustworthy as a push run --
        # rejecting it would be a false failure on a perfectly genuine run.
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        for run in runs.values():
            run["event"] = "schedule"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertEqual(failures, [])
        self.assertEqual(len(verified), len(write_ci_proof.REQUIRED_CHECK_RUNS))

    def test_a_workflow_dispatch_run_against_a_non_main_branch_is_rejected(self) -> None:
        # workflow_dispatch can target a feature ref (e2e.yml documents this
        # explicitly for pre-merge validation); head_sha pinning already
        # makes this hard to exploit, but head_branch is cheap,
        # unconditional defense-in-depth on top of that.
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        target_run_id = jobs[100]["run_id"]
        runs[target_run_id]["event"] = "workflow_dispatch"
        runs[target_run_id]["head_branch"] = "some-feature-branch"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("head_branch" in failure for failure in failures))

    def test_a_resolved_job_with_a_mismatched_name_is_rejected(self) -> None:
        # If check_run.id and job.id were ever allocated from separate ID
        # spaces, this is what would catch it: the job actually resolved to
        # must be the job that produced the check-run being verified.
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        jobs[100]["name"] = "some other job entirely"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("check-run/job correlation is broken" in failure for failure in failures))

    def test_a_forks_head_repository_is_rejected(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        target_run_id = jobs[100]["run_id"]
        runs[target_run_id]["head_repository"] = {"full_name": "attacker/rookie-cookies"}
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("not a fork" in failure for failure in failures))

    def test_a_mismatched_head_sha_between_job_and_target_is_rejected(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        jobs[100]["head_sha"] = "b" * 40
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("head_sha" in failure for failure in failures))

    def test_a_run_conclusion_that_is_not_success_is_rejected(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        target_run_id = jobs[100]["run_id"]
        runs[target_run_id]["conclusion"] = "cancelled"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("run conclusion is" in failure for failure in failures))

    def test_a_check_run_conclusion_that_is_not_success_is_rejected(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        check_runs["check_runs"][0]["conclusion"] = "failure"
        with mock.patch.object(
            write_ci_proof, "gh_api", fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA)
        ):
            _verified, failures = write_ci_proof.verify_required_checks(REPO, COMMIT_SHA)

        self.assertTrue(any("conclusion is" in failure for failure in failures))


class MainTests(unittest.TestCase):
    def test_a_genuine_pass_writes_a_digest_bound_proof(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest-digest",
                    MANIFEST_DIGEST,
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            proof = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(proof["schema_version"], 1)
            self.assertEqual(proof["manifest_digest"], MANIFEST_DIGEST)
            self.assertEqual(proof["commit_sha"], COMMIT_SHA)
            self.assertEqual(len(proof["checks"]), len(write_ci_proof.REQUIRED_CHECK_RUNS))
            recomputed = jcs.digest({key: value for key, value in proof.items() if key != "proof_digest"})
            self.assertEqual(proof["proof_digest"], recomputed)

    def test_failures_are_reported_and_no_proof_is_written(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        check_runs["check_runs"] = [
            entry for entry in check_runs["check_runs"] if entry["name"] != "check (ubuntu-latest)"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest-digest",
                    MANIFEST_DIGEST,
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())

    def test_manifest_flag_reads_the_digest_from_a_real_manifest_file(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_text(
                json.dumps({"release": {"manifest_digest": MANIFEST_DIGEST}, "artifacts": []}),
                encoding="utf-8",
            )
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            proof = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(proof["manifest_digest"], MANIFEST_DIGEST)

    def test_manifest_flag_fails_closed_on_a_missing_digest_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_text(json.dumps({"release": {}, "artifacts": []}), encoding="utf-8")
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())

    def test_manifest_flag_fails_closed_on_a_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "does-not-exist.json"
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())

    def test_manifest_flag_fails_closed_on_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_text("{not valid json", encoding="utf-8")
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())

    def test_manifest_flag_fails_closed_on_a_non_string_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_text(
                json.dumps({"release": {"manifest_digest": 12345}, "artifacts": []}), encoding="utf-8"
            )
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())

    def test_a_manifest_read_failure_is_reported_cleanly_without_advisory(self) -> None:
        # Non-advisory counterpart to the advisory manifest-read-failure test
        # above: main()'s new backstop except clause must produce the same
        # clean, reported-problem failure (exit 1, informative message) rather
        # than a raw uncaught-exception traceback, regardless of --advisory.
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_bytes(b"\xff\xfe not valid utf-8")
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                ],
            ), mock.patch("builtins.print") as fake_print:
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())
            printed = "\n".join(str(call.args[0]) for call in fake_print.call_args_list if call.args)
            self.assertIn("unexpected error", printed)

    def test_advisory_exits_zero_and_prints_a_warning_annotation_on_failure(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        check_runs["check_runs"] = [
            entry for entry in check_runs["check_runs"] if entry["name"] != "check (ubuntu-latest)"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest-digest",
                    MANIFEST_DIGEST,
                    "--output",
                    str(output),
                    "--advisory",
                ],
            ), mock.patch("builtins.print") as fake_print:
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0, "advisory mode must never exit non-zero")
            self.assertFalse(output.exists())
            # GitHub Actions only recognizes `::warning::` as a workflow-command
            # annotation when it is the *entire* content of a single stdout
            # print -- not merely present somewhere in the combined output, and
            # not sharing a call (or a `file=` kwarg routing it to stderr
            # instead) with anything else. A substring-anywhere check would
            # still pass if a future regression buried the marker mid-line or
            # sent it to stderr, silently breaking the visible annotation while
            # this test kept passing.
            warning_calls = [
                call
                for call in fake_print.call_args_list
                if call.args and str(call.args[0]).startswith("::warning::")
            ]
            self.assertEqual(len(warning_calls), 1, fake_print.call_args_list)
            (warning_call,) = warning_calls
            self.assertNotIn("\n", str(warning_call.args[0]))
            self.assertNotIn("file", warning_call.kwargs, "warning must go to stdout, not stderr")
            detail = "\n".join(
                str(call.args[0]) for call in fake_print.call_args_list if call.args and call.kwargs.get("file")
            )
            self.assertIn("check (ubuntu-latest)", detail)

    def test_advisory_and_manifest_flag_together_report_the_real_failure(self) -> None:
        # The exact combination every publish workflow actually uses --
        # `--manifest` (not `--manifest-digest`) together with `--advisory` --
        # exercised together rather than only independently, so a regression
        # in how the two interact (e.g. an exception from manifest-reading
        # bypassing the --advisory wrapper) would be caught here.
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        check_runs["check_runs"] = [
            entry for entry in check_runs["check_runs"] if entry["name"] != "check (ubuntu-latest)"
        ]
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_text(
                json.dumps({"release": {"manifest_digest": MANIFEST_DIGEST}, "artifacts": []}),
                encoding="utf-8",
            )
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                    "--advisory",
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())

    def test_advisory_reports_a_manifest_read_failure_instead_of_crashing(self) -> None:
        # A malformed --manifest file (invalid UTF-8) raises UnicodeDecodeError,
        # which is not in _resolve_manifest_digest's own except tuple -- this
        # proves main()'s outer backstop catches it too, rather than letting an
        # uncaught exception hard-block the calling workflow step despite
        # --advisory.
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "release-scan-manifest.json"
            manifest_path.write_bytes(b"\xff\xfe not valid utf-8")
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest",
                    str(manifest_path),
                    "--output",
                    str(output),
                    "--advisory",
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())

    def test_advisory_reports_a_control_failure_instead_of_crashing(self) -> None:
        # verify_required_checks' initial commits/{sha}/check-runs call can
        # itself raise ControlFailure (e.g. a transient API error) -- a
        # different code path than a populated `failures` list, and one this
        # PR's refactor of main() specifically touched.
        def raising_gh_api(path: str, *, repo: str):
            raise write_ci_proof.ControlFailure("boom: simulated API failure")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(write_ci_proof, "gh_api", raising_gh_api), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest-digest",
                    MANIFEST_DIGEST,
                    "--output",
                    str(output),
                    "--advisory",
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            self.assertFalse(output.exists())

    def test_advisory_exits_zero_and_writes_the_proof_on_success(self) -> None:
        check_runs, jobs, runs = build_good_fixture(REPO, COMMIT_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "ci-proof.json"
            with mock.patch.object(
                write_ci_proof,
                "gh_api",
                fake_gh_api_for(check_runs, jobs, runs, commit_sha=COMMIT_SHA),
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "write-ci-proof.py",
                    "--repo",
                    REPO,
                    "--commit-sha",
                    COMMIT_SHA,
                    "--manifest-digest",
                    MANIFEST_DIGEST,
                    "--output",
                    str(output),
                    "--advisory",
                ],
            ):
                exit_code = write_ci_proof.main()

            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())


class MainArgumentValidationTests(unittest.TestCase):
    def test_rejects_a_short_commit_sha(self) -> None:
        script_path = REPOSITORY_ROOT / "scripts/write-ci-proof.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--repo",
                REPO,
                "--commit-sha",
                "abc123",
                "--manifest-digest",
                MANIFEST_DIGEST,
                "--output",
                "/tmp/unused-ci-proof.json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("commit SHA", result.stderr)

    def test_rejects_a_malformed_manifest_digest(self) -> None:
        script_path = REPOSITORY_ROOT / "scripts/write-ci-proof.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--repo",
                REPO,
                "--commit-sha",
                COMMIT_SHA,
                "--manifest-digest",
                "too-short",
                "--output",
                "/tmp/unused-ci-proof.json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest digest", result.stderr)

    def test_manifest_digest_and_manifest_are_mutually_exclusive(self) -> None:
        script_path = REPOSITORY_ROOT / "scripts/write-ci-proof.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--repo",
                REPO,
                "--commit-sha",
                COMMIT_SHA,
                "--manifest-digest",
                MANIFEST_DIGEST,
                "--manifest",
                "/tmp/unused-manifest.json",
                "--output",
                "/tmp/unused-ci-proof.json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not allowed with argument", result.stderr)

    def test_neither_manifest_digest_nor_manifest_is_an_error(self) -> None:
        script_path = REPOSITORY_ROOT / "scripts/write-ci-proof.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--repo",
                REPO,
                "--commit-sha",
                COMMIT_SHA,
                "--output",
                "/tmp/unused-ci-proof.json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("one of the arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()
