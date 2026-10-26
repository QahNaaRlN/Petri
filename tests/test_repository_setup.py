"""Offline governance tests. No GitHub account or network access is used."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "configure_github.py"
SPEC = importlib.util.spec_from_file_location("petri_repository_setup", SCRIPT)
setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = setup
SPEC.loader.exec_module(setup)


def protected_response():
    payload = setup.protection_payload()
    result = copy.deepcopy(payload)
    checks = result["required_status_checks"]
    checks["contexts"] = [item["context"] for item in checks["checks"]]
    for key in ("enforce_admins", "required_linear_history", "allow_force_pushes", "allow_deletions",
                "required_conversation_resolution", "block_creations", "lock_branch", "allow_fork_syncing"):
        result[key] = {"enabled": result[key]}
    return result


class FakeGh:
    def __init__(self, *, configured=False, main_exists=True):
        self.repo = {"full_name": setup.REPOSITORY, **setup.REPOSITORY_SETTINGS}
        if not configured:
            self.repo.update(default_branch="master", allow_merge_commit=True, allow_rebase_merge=True,
                             delete_branch_on_merge=False, allow_update_branch=False)
        branch = {"commit": {"sha": "f" * 40}, "protected": configured}
        self.main = copy.deepcopy(branch) if main_exists else None
        self.master = copy.deepcopy(branch)
        self.protection = protected_response() if configured else None
        self.rulesets = []
        self.prs = [] if configured else [{"number": 1, "base": {"ref": "master"}}]
        self.calls = []
        self.fail_mutation = None
        self.mutations = 0

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), copy.deepcopy(kwargs)))
        if args[:3] != ["gh", "api", "--method"]:
            raise AssertionError("unexpected command or shell wrapper")
        if kwargs.get("shell"):
            raise AssertionError("shell use is prohibited")
        method, endpoint = args[3:5]
        base = f"repos/{setup.REPOSITORY}"
        data = json.loads(kwargs["input"]) if kwargs.get("input") is not None else None
        if method != "GET":
            self.mutations += 1
            if self.mutations == self.fail_mutation:
                return subprocess.CompletedProcess(args, 1, "", "gh: secret-token-must-not-be-logged (HTTP 403)")
            if method == "PATCH" and endpoint == base:
                self.repo.update(data)
            elif method == "PUT" and endpoint == f"{base}/branches/main/protection":
                self.protection = protected_response()
                self.main["protected"] = True
            elif method == "PATCH" and endpoint == f"{base}/pulls/1":
                self.prs = []
            elif method == "POST" and endpoint == f"{base}/branches/master/rename":
                self.main, self.master = self.master, None
                self.repo["default_branch"] = "main"
            else:
                raise AssertionError(f"unexpected mutation: {method} {endpoint}")
            return subprocess.CompletedProcess(args, 0, "{}", "")
        if endpoint == base:
            response = self.repo
        elif endpoint == f"{base}/branches/main":
            response = self.main
        elif endpoint == f"{base}/branches/master":
            response = self.master
        elif endpoint.endswith("/protection"):
            response = self.protection
        elif endpoint == f"{base}/rulesets?includes_parents=true&per_page=100":
            response = self.rulesets
        elif endpoint == f"{base}/pulls?state=open&base=master&per_page=100":
            response = self.prs
        elif endpoint == f"{base}/pulls/1":
            response = {"number": 1, "base": {"ref": "master" if self.prs else "main"}}
        else:
            raise AssertionError(f"unexpected read: {method} {endpoint}")
        if response is None:
            return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)")
        return subprocess.CompletedProcess(args, 0, json.dumps(response), "")


class RepositorySetupTests(unittest.TestCase):
    def run_setup(self, gh, *args):
        parsed = setup.parser().parse_args(args)
        with patch.object(setup.subprocess, "run", side_effect=gh):
            return setup.execute(parsed)

    def test_default_dry_run_reads_snapshot_without_mutating(self):
        gh = FakeGh()
        code, report = self.run_setup(gh)
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "planned")
        self.assertTrue(report["planned"])
        self.assertEqual(gh.mutations, 0)
        self.assertTrue(all(call[0][3] == "GET" for call in gh.calls))
        self.assertEqual(report["before"]["settings"]["default_branch"], "master")

    def test_apply_sets_exact_policy_then_reads_it_back(self):
        gh = FakeGh()
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual((code, report["status"]), (0, "verified"))
        self.assertFalse(report["issues"])
        self.assertEqual(len(report["completed"]), 4)
        self.assertEqual(gh.repo["default_branch"], "main")
        self.assertIsNotNone(gh.master)  # Existing legacy branch is preserved.
        self.assertEqual(setup.parse_contexts(gh.protection),
                         {name: 15368 for name in setup.REQUIRED_CONTEXTS})
        self.assertTrue(all(call[0][3] != "DELETE" for call in gh.calls))
        writes = [call for call in gh.calls if call[0][3] != "GET"]
        for args, kwargs in writes:
            self.assertEqual(args[-2:], ["--input", "-"])
            self.assertIsInstance(json.loads(kwargs["input"]), dict)
            self.assertNotIn("shell", kwargs)
        # Required native check contains a semicolon and remains a JSON value.
        self.assertIn("Native Linux isolation (required; no skipped success)", writes[1][1]["input"])

    def test_failure_stops_before_later_mutations_and_preserves_atomic_report(self):
        gh = FakeGh()
        gh.fail_mutation = 2
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            code, report = self.run_setup(gh, "--apply", "--report", str(path))
            persisted = json.loads(path.read_text())
            self.assertEqual(persisted, report)
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])
        self.assertEqual((code, report["status"]), (1, "failed"))
        self.assertEqual(gh.mutations, 2)
        self.assertEqual(len(report["completed"]), 1)
        self.assertIn("HTTP 403", report["error"])
        self.assertNotIn("secret-token", json.dumps(report))
        self.assertEqual(gh.prs[0]["base"]["ref"], "master")
        self.assertEqual(gh.repo["default_branch"], "master")
        self.assertTrue(report["attempted"]["endpoint"].endswith("/protection"))

    def test_first_write_denied_does_not_attempt_protection_or_pr_updates(self):
        gh = FakeGh()
        gh.fail_mutation = 1
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertEqual(gh.mutations, 1)
        self.assertEqual(report["completed"], [])
        self.assertEqual(gh.repo["default_branch"], "master")
        self.assertIn("Administration", report["error"])

    def test_already_configured_apply_is_idempotent(self):
        gh = FakeGh(configured=True)
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual((code, report["status"]), (0, "verified"))
        self.assertEqual(gh.mutations, 0)
        self.assertEqual(report["planned"], [])

    def test_verify_is_read_only_and_checks_values_not_http_success(self):
        for configured in (False, True):
            with self.subTest(configured=configured):
                gh = FakeGh(configured=configured)
                code, report = self.run_setup(gh, "--verify")
                self.assertEqual(code, 0 if configured else 1)
                self.assertEqual(gh.mutations, 0)
                self.assertEqual(report["status"], "verified" if configured else "mismatch")
        gh = FakeGh(configured=True)
        gh.protection["enforce_admins"]["enabled"] = False
        gh.protection["allow_deletions"]["enabled"] = True
        gh.protection["required_status_checks"]["strict"] = False
        code, report = self.run_setup(gh, "--verify")
        self.assertEqual(code, 1)
        self.assertGreaterEqual(len(report["issues"]), 3)

    def test_context_parser_requires_exact_names_and_app_bindings(self):
        protection = protected_response()
        self.assertEqual(set(setup.parse_contexts(protection)), set(setup.REQUIRED_CONTEXTS))
        protection["required_status_checks"]["checks"][0]["app_id"] = -1
        self.assertTrue(setup.protection_issues(protection))
        protection["required_status_checks"]["checks"].append({"context": setup.REQUIRED_CONTEXTS[0], "app_id": 15368})
        with self.assertRaises(setup.SetupError):
            setup.parse_contexts(protection)
        with self.assertRaises(setup.SetupError):
            setup.parse_contexts({"required_status_checks": {"contexts": ["one"], "checks": [{"context": "two", "app_id": 15368}]}})
        legacy = {"required_status_checks": {"contexts": list(setup.REQUIRED_CONTEXTS)}}
        self.assertTrue(all(value is None for value in setup.parse_contexts(legacy).values()))

    def test_stronger_existing_reviews_and_extra_checks_are_not_removed(self):
        for stronger in ("reviews", "extra-check", "push-restrictions", "locked", "different-app"):
            with self.subTest(stronger=stronger):
                gh = FakeGh(configured=True)
                if stronger == "reviews":
                    gh.protection["required_pull_request_reviews"]["required_approving_review_count"] = 2
                elif stronger == "extra-check":
                    gh.protection["required_status_checks"]["contexts"].append("security review")
                    gh.protection["required_status_checks"]["checks"].append({"context": "security review", "app_id": 15368})
                elif stronger == "push-restrictions":
                    gh.protection["restrictions"] = {"users": []}
                    gh.protection["enforce_admins"]["enabled"] = False
                elif stronger == "locked":
                    gh.protection["lock_branch"]["enabled"] = True
                    gh.protection["enforce_admins"]["enabled"] = False
                else:
                    gh.protection["required_status_checks"]["checks"][0]["app_id"] = 999
                code, report = self.run_setup(gh, "--apply")
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(gh.mutations, 0)

    def test_active_rulesets_require_manual_review_before_replacing_protection(self):
        gh = FakeGh()
        gh.rulesets = [{"id": 123, "enforcement": "active"}]
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertIn("rulesets", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_rename_occurs_only_when_main_absent_and_master_is_default(self):
        gh = FakeGh(main_exists=False)
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual((code, report["status"]), (0, "verified"))
        writes = [call[0] for call in gh.calls if call[0][3] != "GET"]
        self.assertEqual(writes[0][3], "POST")
        self.assertTrue(writes[0][4].endswith("/branches/master/rename"))
        self.assertIsNone(gh.master)
        gh = FakeGh(main_exists=False)
        gh.repo["default_branch"] = "develop"
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertEqual(gh.mutations, 0)

    def test_wrong_repository_and_shell_fragments_are_rejected_before_gh(self):
        for repo in ("someone/else", "QahNaaRlN/Petri;touch /tmp/unwanted", "../Petri"):
            with self.subTest(repo=repo):
                with patch.object(setup.subprocess, "run") as run:
                    with patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                        setup.main(["--repo", repo])
                    self.assertEqual(error.exception.code, 2)
                    run.assert_not_called()

    def test_read_access_failure_is_not_treated_as_unprotected(self):
        def denied(args, **kwargs):
            return subprocess.CompletedProcess(args, 1, "", "gh: Resource not accessible (HTTP 403)")
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=denied) as run:
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(report["completed"], [])
        self.assertIn("HTTP 403", report["error"])

    def test_report_write_failure_prevents_mutations(self):
        gh = FakeGh()
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=gh), \
                patch.object(setup, "save_report", side_effect=OSError("report unavailable")):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertEqual(gh.mutations, 0)
        self.assertTrue(report["report_write_failed"])

    def test_unprotected_branch_avoids_administration_read_endpoint(self):
        gh = FakeGh()
        code, _report = self.run_setup(gh)
        self.assertEqual(code, 0)
        self.assertFalse(any(call[0][4].endswith("/protection") for call in gh.calls))

    def test_missing_protected_flag_is_not_assumed_false(self):
        gh = FakeGh()
        del gh.main["protected"]
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertIn("protected flag", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_protected_branch_denied_read_is_not_assumed_unprotected(self):
        gh = FakeGh(configured=True)
        def deny_protection(args, **kwargs):
            if args[4].endswith("/protection"):
                return subprocess.CompletedProcess(args, 1, "", "gh: Forbidden (HTTP 403)")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=deny_protection):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 403", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_hostname_is_pinned_even_when_gh_host_environment_differs(self):
        gh = FakeGh()
        with patch.dict(os.environ, {"GH_HOST": "example.invalid"}):
            code, _report = self.run_setup(gh)
        self.assertEqual(code, 0)
        for args, _kwargs in gh.calls:
            self.assertIn("--hostname", args)
            self.assertEqual(args[args.index("--hostname") + 1], "github.com")

    def test_policy_strengthened_after_plan_stops_before_first_write(self):
        gh = FakeGh()
        reads = 0
        def concurrent_admin(args, **kwargs):
            nonlocal reads
            if args[3] == "GET" and args[4] == f"repos/{setup.REPOSITORY}":
                reads += 1
                if reads == 2:
                    gh.protection = protected_response()
                    gh.protection["required_pull_request_reviews"]["required_approving_review_count"] = 2
                    gh.main["protected"] = True
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=concurrent_admin):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("stronger", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_verify_refuses_to_infer_effective_policy_from_active_rulesets(self):
        gh = FakeGh(configured=True)
        gh.rulesets = [{"id": 123, "enforcement": "active"}]
        code, report = self.run_setup(gh, "--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any("rulesets" in issue for issue in report["issues"]))
        self.assertEqual(gh.mutations, 0)

    def test_required_signatures_are_not_silently_lost_during_update(self):
        gh = FakeGh(configured=True)
        gh.protection["required_signatures"] = {"enabled": True}
        gh.protection["enforce_admins"]["enabled"] = False
        # Fake PUT intentionally loses signatures, unlike the expected separate
        # GitHub signatures endpoint. The script must fail rather than claim OK.
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertIn("signatures", report["error"])
        self.assertEqual(gh.mutations, 1)

    def test_http_success_without_actual_update_stops_without_retry_loop(self):
        gh = FakeGh()
        def accepted_without_update(args, **kwargs):
            if args[3] != "GET":
                gh.mutations += 1
                return subprocess.CompletedProcess(args, 0, "{}", "")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=accepted_without_update):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("actual settings did not change", report["error"])
        self.assertEqual(gh.mutations, 1)

    def test_concurrent_pr_retarget_to_unrelated_branch_is_not_overwritten(self):
        gh = FakeGh(configured=True)
        gh.prs = [{"number": 1, "base": {"ref": "master"}}]
        def concurrent_retarget(args, **kwargs):
            if args[3] == "GET" and args[4].endswith("/pulls/1"):
                return subprocess.CompletedProcess(args, 0, json.dumps({"number": 1, "base": {"ref": "release/other"}}), "")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=concurrent_retarget):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("base changed", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_concurrent_pr_retarget_to_main_is_skipped(self):
        gh = FakeGh(configured=True)
        gh.prs = [{"number": 1, "base": {"ref": "master"}}]
        def concurrent_retarget(args, **kwargs):
            if args[3] == "GET" and args[4].endswith("/pulls/1"):
                gh.prs = []
                return subprocess.CompletedProcess(args, 0, json.dumps({"number": 1, "base": {"ref": "main"}}), "")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply"])
        with patch.object(setup.subprocess, "run", side_effect=concurrent_retarget):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 0)
        self.assertEqual(gh.mutations, 0)
        self.assertEqual(len(report["skipped"]), 1)

    def test_pull_request_bypass_allowances_are_removed_and_verified(self):
        gh = FakeGh(configured=True)
        gh.protection["required_pull_request_reviews"]["bypass_pull_request_allowances"] = {"users": [{"login": "someone"}], "teams": [], "apps": []}
        code, report = self.run_setup(gh, "--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any("bypass" in issue for issue in report["issues"]))
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 0)
        self.assertEqual(gh.protection["required_pull_request_reviews"]["bypass_pull_request_allowances"], {"users": [], "teams": [], "apps": []})

    def test_default_branch_switch_follows_successful_main_protection(self):
        gh = FakeGh()
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 0)
        writes = [(args[3], args[4], json.loads(kwargs["input"]))
                  for args, kwargs in gh.calls if args[3] != "GET"]
        protection_index = next(i for i, action in enumerate(writes) if action[0] == "PUT")
        default_index = next(i for i, action in enumerate(writes) if action[2].get("default_branch") == "main")
        self.assertLess(protection_index, default_index)

    def test_older_gh_pagination_decodes_multiple_json_documents_without_slurp(self):
        response = ' [{"id": 1, "name": "a}b"}]\n[{"id": 2}] \n [] '
        with patch.object(setup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, response, "")) as run:
            pages = setup.GitHub().pages(f"repos/{setup.REPOSITORY}/rulesets")
        self.assertEqual(pages, [{"id": 1, "name": "a}b"}, {"id": 2}])
        args = run.call_args.args[0]
        self.assertIn("--paginate", args)
        self.assertNotIn("--slurp", args)

    def test_protected_branch_with_hidden_or_changed_policy_404_fails_closed(self):
        gh = FakeGh(configured=True)
        gh.protection = None
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertIn("policy is unavailable", report["error"])
        self.assertEqual(gh.mutations, 0)


if __name__ == "__main__":
    unittest.main()
