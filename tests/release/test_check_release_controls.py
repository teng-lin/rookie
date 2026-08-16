from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_release_controls", REPOSITORY_ROOT / "scripts/check-release-controls.py"
)
assert SPEC is not None and SPEC.loader is not None
check_release_controls = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_release_controls
SPEC.loader.exec_module(check_release_controls)


GOOD_ENVIRONMENT = {"can_admins_bypass": False, "deployment_branch_policy": {"custom_branch_policies": True}}
GOOD_POLICIES = {"branch_policies": [{"name": "main", "type": "branch"}, {"name": "v*", "type": "tag"}]}

GOOD_RULESETS_LIST = [
    {"id": 1, "name": "release-tag-creation"},
    {"id": 2, "name": "release-tag-immutable"},
]
GOOD_CREATION_RULESET = {
    "target": "tag",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
    "rules": [{"type": "creation"}],
    "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole"}],
}
GOOD_IMMUTABLE_RULESET = {
    "target": "tag",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"]}},
    "rules": [{"type": "deletion"}, {"type": "update"}],
    "bypass_actors": [],
}


def fake_gh_api_for(overrides: dict[str, object]):
    def fake_gh_api(path: str, *, repo: str):
        if path in overrides:
            return overrides[path]
        if path == "environments/release":
            return GOOD_ENVIRONMENT
        if path == "environments/release/deployment-branch-policies":
            return GOOD_POLICIES
        if path == "rulesets":
            return GOOD_RULESETS_LIST
        if path == "rulesets/1":
            return GOOD_CREATION_RULESET
        if path == "rulesets/2":
            return GOOD_IMMUTABLE_RULESET
        raise AssertionError(f"unexpected gh_api call: {path}")

    return fake_gh_api


class ReleaseEnvironmentTests(unittest.TestCase):
    def test_passes_when_locked_down(self) -> None:
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for({})):
            self.assertEqual(check_release_controls.check_release_environment("owner/repo"), [])

    def test_fails_when_admin_bypass_enabled(self) -> None:
        overrides = {"environments/release": {**GOOD_ENVIRONMENT, "can_admins_bypass": True}}
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_release_environment("owner/repo")
        self.assertTrue(any("can_admins_bypass" in failure for failure in failures))

    def test_fails_when_deployment_refs_are_wrong(self) -> None:
        overrides = {
            "environments/release/deployment-branch-policies": {
                "branch_policies": [{"name": "main", "type": "branch"}]
            }
        }
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_release_environment("owner/repo")
        self.assertTrue(any("deployment refs" in failure for failure in failures))

    def test_fails_when_not_using_custom_branch_policies(self) -> None:
        overrides = {"environments/release": {**GOOD_ENVIRONMENT, "deployment_branch_policy": {}}}
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_release_environment("owner/repo")
        self.assertTrue(any("custom_branch_policies" in failure for failure in failures))


class TagRulesetTests(unittest.TestCase):
    def test_passes_when_both_rulesets_correct(self) -> None:
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for({})):
            self.assertEqual(check_release_controls.check_tag_rulesets("owner/repo"), [])

    def test_fails_when_a_ruleset_is_missing(self) -> None:
        overrides = {"rulesets": [{"id": 1, "name": "release-tag-creation"}]}
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_tag_rulesets("owner/repo")
        self.assertTrue(any("release-tag-immutable" in failure and "missing" in failure for failure in failures))

    def test_fails_when_immutable_ruleset_has_a_bypass_actor(self) -> None:
        overrides = {
            "rulesets/2": {
                **GOOD_IMMUTABLE_RULESET,
                "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole"}],
            }
        }
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_tag_rulesets("owner/repo")
        self.assertTrue(any("release-tag-immutable" in failure and "bypass actor" in failure for failure in failures))

    def test_fails_when_bypass_actor_id_matches_but_type_does_not(self) -> None:
        # A Team or Integration that happens to share id 5 with the
        # RepositoryRole "Admin" this ruleset is meant to allow must not be
        # silently accepted as an equivalent bypass grant.
        overrides = {
            "rulesets/1": {
                **GOOD_CREATION_RULESET,
                "bypass_actors": [{"actor_id": 5, "actor_type": "Team"}],
            }
        }
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_tag_rulesets("owner/repo")
        self.assertTrue(any("release-tag-creation" in failure and "bypass actor" in failure for failure in failures))

    def test_fails_when_enforcement_is_not_active(self) -> None:
        overrides = {"rulesets/1": {**GOOD_CREATION_RULESET, "enforcement": "disabled"}}
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_tag_rulesets("owner/repo")
        self.assertTrue(any("enforcement" in failure for failure in failures))

    def test_fails_when_ref_pattern_is_wrong(self) -> None:
        overrides = {
            "rulesets/2": {
                **GOOD_IMMUTABLE_RULESET,
                "conditions": {"ref_name": {"include": ["refs/tags/*"]}},
            }
        }
        with mock.patch.object(check_release_controls, "gh_api", fake_gh_api_for(overrides)):
            failures = check_release_controls.check_tag_rulesets("owner/repo")
        self.assertTrue(any("ref_name include" in failure for failure in failures))


class RequiredChecksTests(unittest.TestCase):
    def test_passes_when_every_required_check_succeeded(self) -> None:
        response = {
            "check_runs": [
                {"name": name, "status": "completed", "conclusion": "success", "started_at": "2026-01-01T00:00:00Z"}
                for name in check_release_controls.REQUIRED_CHECK_RUNS
            ]
        }
        with mock.patch.object(check_release_controls, "gh_api", return_value=response):
            failures = check_release_controls.check_required_checks("owner/repo", "a" * 40)
        self.assertEqual(failures, [])

    def test_fails_when_a_required_check_is_missing(self) -> None:
        response = {"check_runs": []}
        with mock.patch.object(check_release_controls, "gh_api", return_value=response):
            failures = check_release_controls.check_required_checks("owner/repo", "a" * 40)
        self.assertEqual(len(failures), len(check_release_controls.REQUIRED_CHECK_RUNS))

    def test_fails_when_conclusion_is_not_success(self) -> None:
        response = {
            "check_runs": [
                {"name": name, "status": "completed", "conclusion": "failure", "started_at": "2026-01-01T00:00:00Z"}
                for name in check_release_controls.REQUIRED_CHECK_RUNS
            ]
        }
        with mock.patch.object(check_release_controls, "gh_api", return_value=response):
            failures = check_release_controls.check_required_checks("owner/repo", "a" * 40)
        self.assertEqual(len(failures), len(check_release_controls.REQUIRED_CHECK_RUNS))

    def test_uses_the_most_recently_started_rerun(self) -> None:
        name = check_release_controls.REQUIRED_CHECK_RUNS[0]
        response = {
            "check_runs": [
                {"name": name, "status": "completed", "conclusion": "failure", "started_at": "2026-01-01T00:00:00Z"},
                {"name": name, "status": "completed", "conclusion": "success", "started_at": "2026-01-02T00:00:00Z"},
            ]
            + [
                {"name": other, "status": "completed", "conclusion": "success", "started_at": "2026-01-01T00:00:00Z"}
                for other in check_release_controls.REQUIRED_CHECK_RUNS[1:]
            ]
        }
        with mock.patch.object(check_release_controls, "gh_api", return_value=response):
            failures = check_release_controls.check_required_checks("owner/repo", "a" * 40)
        self.assertEqual(failures, [])


class MainArgumentValidationTests(unittest.TestCase):
    def test_rejects_a_short_commit_sha(self) -> None:
        import subprocess

        result = subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "scripts/check-release-controls.py"), "--repo", "o/r", "--commit-sha", "abc123"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("40-character", result.stderr)


if __name__ == "__main__":
    unittest.main()
