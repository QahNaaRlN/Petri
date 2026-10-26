"""Offline governance tests. No GitHub account or network access is used."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import shutil
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
    def __init__(self, *, configured=False, main_exists=True, dev_exists=True):
        self.repo = {"full_name": setup.REPOSITORY, **setup.REPOSITORY_SETTINGS}
        if not configured:
            self.repo.update(default_branch="master", allow_merge_commit=True, allow_rebase_merge=True,
                             delete_branch_on_merge=False, allow_update_branch=False)
        branch = {"commit": {"sha": "f" * 40}, "protected": configured}
        self.main = copy.deepcopy(branch) if main_exists else None
        self.master = copy.deepcopy(branch)
        self.dev = copy.deepcopy(branch) if dev_exists else None
        self.protection = protected_response() if configured else None
        self.dev_protection = protected_response() if configured and dev_exists else None
        self.comparison_status = "identical"
        self.master_ahead = 0
        self.master_head_prs = []
        self.before_lease_push = None
        self.rulesets = []
        self.prs = [] if configured else [{"number": 1, "base": {"ref": "master"}, "head": {"ref": "feat/demo"}}]
        self.calls = []
        self.fail_mutation = None
        self.mutations = 0

    def __call__(self, args, **kwargs):
        self.calls.append((list(args), copy.deepcopy(kwargs)))
        if args[0] == "git":
            if "get-url" in args:
                return subprocess.CompletedProcess(args, 0, setup.GIT_REMOTE + "\n", "")
            if "push" in args:
                self.mutations += 1
                if self.before_lease_push:
                    self.before_lease_push()
                lease = next(value for value in args if value.startswith("--force-with-lease="))
                expected = lease.rsplit(":", 1)[1]
                if self.mutations == self.fail_mutation or self.master["commit"]["sha"] != expected:
                    return subprocess.CompletedProcess(args, 1, "", "secret-token-must-not-be-logged; stale lease")
                self.master = None
            return subprocess.CompletedProcess(args, 0, "", "")
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
            elif method == "PUT" and endpoint == f"{base}/branches/dev/protection":
                self.dev_protection = protected_response()
                self.dev["protected"] = True
            elif method == "POST" and endpoint == f"{base}/git/refs":
                self.dev = {"commit": {"sha": data["sha"]}, "protected": False}
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
        elif endpoint == f"{base}/branches/dev":
            response = self.dev
        elif endpoint == f"{base}/branches/dev/protection":
            response = self.dev_protection
        elif endpoint.endswith("/protection"):
            response = self.protection
        elif endpoint == f"{base}/rulesets?includes_parents=true&per_page=100":
            response = self.rulesets
        elif endpoint == f"{base}/pulls?state=open&base=master&per_page=100":
            response = self.prs
        elif endpoint == f"{base}/pulls?state=open&head=QahNaaRlN:master&per_page=100":
            response = self.master_head_prs
        elif endpoint == f"{base}/pulls/1":
            response = {"number": 1, "base": {"ref": "master" if self.prs else "dev"}, "head": {"ref": "feat/demo"}}
        elif endpoint.startswith(f"{base}/compare/"):
            response = {"status": self.comparison_status, "ahead_by": self.master_ahead,
                        "base_commit": {"sha": self.main["commit"]["sha"]},
                        "merge_base_commit": {"sha": self.master["commit"]["sha"]}}
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
        self.assertEqual(len(report["completed"]), 5)
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
        gh.prs = [{"number": 1, "base": {"ref": "master"}, "head": {"ref": "feat/demo"}}]
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

    def test_concurrent_pr_retarget_to_dev_is_skipped(self):
        gh = FakeGh(configured=True)
        gh.prs = [{"number": 1, "base": {"ref": "master"}, "head": {"ref": "feat/demo"}}]
        def concurrent_retarget(args, **kwargs):
            if args[3] == "GET" and args[4].endswith("/pulls/1"):
                gh.prs = []
                return subprocess.CompletedProcess(args, 0, json.dumps({"number": 1, "base": {"ref": "dev"}}), "")
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

    def test_dev_creation_uses_main_commit_then_protects_both_branches(self):
        gh = FakeGh(dev_exists=False)
        main_sha = gh.main["commit"]["sha"]
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual((code, report["status"]), (0, "verified"))
        self.assertEqual(gh.dev["commit"]["sha"], main_sha)
        self.assertEqual(setup.parse_contexts(gh.dev_protection), setup.parse_contexts(gh.protection))
        writes = report["completed"]
        creation = next(i for i, action in enumerate(writes) if action["endpoint"].endswith("/git/refs"))
        protection = next(i for i, action in enumerate(writes) if action["endpoint"].endswith("/branches/dev/protection"))
        self.assertLess(creation, protection)
        self.assertEqual(writes[creation]["payload"], {"ref": "refs/heads/dev", "sha": main_sha})

    def test_verify_requires_dev_exists_and_matches_protection(self):
        gh = FakeGh(configured=True, dev_exists=False)
        code, report = self.run_setup(gh, "--verify")
        self.assertEqual(code, 1)
        self.assertIn("dev branch does not exist", report["issues"])
        gh = FakeGh(configured=True)
        gh.dev_protection["enforce_admins"]["enabled"] = False
        code, report = self.run_setup(gh, "--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any("dev must enable enforce_admins" in issue for issue in report["issues"]))

    def test_merge_commit_profile_preserves_long_lived_branch_dag(self):
        self.assertTrue(setup.REPOSITORY_SETTINGS["allow_merge_commit"])
        self.assertFalse(setup.REPOSITORY_SETTINGS["allow_squash_merge"])
        self.assertFalse(setup.REPOSITORY_SETTINGS["allow_rebase_merge"])
        self.assertFalse(setup.protection_payload()["required_linear_history"])
        gh = FakeGh(configured=True)
        gh.dev_protection["required_linear_history"]["enabled"] = True
        code, report = self.run_setup(gh, "--apply")
        self.assertEqual(code, 1)
        self.assertIn("linear-history", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_delete_master_flag_is_plan_only_without_apply(self):
        gh = FakeGh()
        code, report = self.run_setup(gh, "--delete-master")
        self.assertEqual(code, 0)
        self.assertEqual(gh.mutations, 0)
        self.assertEqual(report["planned"][-1]["method"], setup.LEASE_DELETE)
        self.assertEqual(report["planned"][-1]["endpoint"], setup.GIT_REMOTE)
        self.assertTrue(any("/compare/" in args[4] for args, _ in gh.calls))

    def test_master_deletion_occurs_last_after_protections_default_and_prs(self):
        gh = FakeGh()
        code, report = self.run_setup(gh, "--apply", "--delete-master")
        self.assertEqual((code, report["status"]), (0, "verified"))
        self.assertIsNone(gh.master)
        self.assertEqual(report["completed"][-1]["method"], setup.LEASE_DELETE)
        self.assertTrue(gh.main["protected"])
        self.assertTrue(gh.dev["protected"])
        self.assertEqual(gh.repo["default_branch"], "main")
        self.assertEqual(gh.prs, [])
        deletion_index = next(i for i, call in enumerate(gh.calls) if call[0][0] == "git")
        immediate_reads = [call[0][4] for call in gh.calls[max(0, deletion_index-2):deletion_index]]
        self.assertTrue(immediate_reads[0].endswith("/branches/main"))
        self.assertTrue(immediate_reads[1].endswith("/branches/master"))

    def test_master_ancestor_behind_main_is_safe_without_equal_sha(self):
        gh = FakeGh(configured=True)
        gh.master["commit"]["sha"] = "e" * 40
        gh.comparison_status = "behind"
        code, report = self.run_setup(gh, "--apply", "--delete-master")
        self.assertEqual((code, report["status"]), (0, "verified"))
        self.assertIsNone(gh.master)

    def test_unmerged_or_unverified_master_commits_are_never_deleted(self):
        for status, ahead in (("ahead", 1), ("diverged", 2), ("behind", 1)):
            with self.subTest(status=status, ahead=ahead):
                gh = FakeGh(configured=True)
                gh.comparison_status, gh.master_ahead = status, ahead
                code, report = self.run_setup(gh, "--apply", "--delete-master")
                self.assertEqual(code, 1)
                self.assertIn("unmerged or unverified", report["error"])
                self.assertEqual(gh.mutations, 0)
                self.assertIsNotNone(gh.master)

    def test_compare_404_is_uncertainty_not_permission_to_delete(self):
        gh = FakeGh(configured=True)
        def missing_compare(args, **kwargs):
            if "/compare/" in args[4]:
                return subprocess.CompletedProcess(args, 1, "", "gh: Not Found (HTTP 404)")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply", "--delete-master"])
        with patch.object(setup.subprocess, "run", side_effect=missing_compare):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertEqual(gh.mutations, 0)
        self.assertIn("HTTP 404", report["error"])

    def test_ref_move_after_compare_prevents_master_deletion(self):
        gh = FakeGh(configured=True)
        comparisons = 0
        def moved_ref(args, **kwargs):
            nonlocal comparisons
            response = gh(args, **kwargs)
            if "/compare/" in args[4]:
                comparisons += 1
                if comparisons == 2:
                    gh.master["commit"]["sha"] = "e" * 40
            return response
        parsed = setup.parser().parse_args(["--apply", "--delete-master"])
        with patch.object(setup.subprocess, "run", side_effect=moved_ref):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("branch moved", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_default_master_or_remaining_legacy_pr_prevents_direct_deletion(self):
        for configured in (False, True):
            gh = FakeGh(configured=configured)
            if configured:
                gh.prs = [{"number": 1, "base": {"ref": "master"}, "head": {"ref": "feat/demo"}}]
            with patch.object(setup.subprocess, "run", side_effect=gh):
                state = setup.snapshot(setup.GitHub(), True)
                with self.assertRaises(setup.SetupError):
                    setup.require_safe_deletion(setup.GitHub(), state)
            self.assertEqual(gh.mutations, 0)

    def test_delete_permission_denial_stops_without_claiming_removed_branch(self):
        gh = FakeGh(configured=True)
        gh.fail_mutation = 1
        code, report = self.run_setup(gh, "--apply", "--delete-master")
        self.assertEqual(code, 1)
        self.assertIn("conditional master deletion", report["error"])
        self.assertEqual(report["attempted"]["method"], setup.LEASE_DELETE)
        self.assertIsNotNone(gh.master)

    def test_verify_master_absence_only_when_explicitly_requested(self):
        gh = FakeGh(configured=True)
        self.assertEqual(self.run_setup(gh, "--verify")[0], 0)
        code, report = self.run_setup(gh, "--verify", "--delete-master")
        self.assertEqual(code, 1)
        self.assertIn("legacy master branch still exists", report["issues"])

    def test_legacy_pr_targets_follow_declared_feature_and_promotion_policy(self):
        self.assertEqual(setup.legacy_pr_target({"head": {"ref": "feat/feature"}}), "dev")
        self.assertEqual(setup.legacy_pr_target({"head": {"ref": "dev", "repo": {"full_name": setup.REPOSITORY}}}), "main")
        with self.assertRaises(setup.SetupError):
            setup.legacy_pr_target({"head": {"ref": "some-other-branch"}})

    def test_master_advance_after_final_read_is_rejected_by_atomic_git_lease(self):
        gh = FakeGh(configured=True)
        gh.before_lease_push = lambda: gh.master["commit"].update(sha="e" * 40)
        code, report = self.run_setup(gh, "--apply", "--delete-master")
        self.assertEqual(code, 1)
        self.assertEqual(gh.master["commit"]["sha"], "e" * 40)
        self.assertIn("conditional master deletion", report["error"])
        self.assertNotIn("secret-token", json.dumps(report))
        self.assertFalse(any(args[0] == "gh" and args[3] == "DELETE" for args, _ in gh.calls))
        push, kwargs = next((args, kwargs) for args, kwargs in gh.calls if args[0] == "git" and "push" in args)
        self.assertIn("--force-with-lease=refs/heads/master:" + "f" * 40, push)
        self.assertEqual(push[-2:], ["origin", ":refs/heads/master"])
        self.assertIn("credential.helper=", push)
        self.assertIn("credential.helper=!gh auth git-credential", push)
        self.assertTrue(any(value.startswith("core.hooksPath=") for value in push))
        self.assertEqual(kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(kwargs["env"]["GIT_ASKPASS"], "")

    def test_fixed_push_url_rewrite_stops_before_git_push(self):
        gh = FakeGh(configured=True)
        def rewritten(args, **kwargs):
            if args[0] == "git" and "get-url" in args:
                return subprocess.CompletedProcess(args, 0, "https://example.invalid/other.git\n", "")
            return gh(args, **kwargs)
        parsed = setup.parser().parse_args(["--apply", "--delete-master"])
        with patch.object(setup.subprocess, "run", side_effect=rewritten):
            code, report = setup.execute(parsed)
        self.assertEqual(code, 1)
        self.assertIn("URL was rewritten", report["error"])
        self.assertFalse(any(args[0] == "git" and "push" in args for args, _ in gh.calls))
        self.assertIsNotNone(gh.master)

    def test_open_master_head_pr_prevents_deletion(self):
        gh = FakeGh(configured=True)
        gh.master_head_prs = [{"number": 9, "head": {"ref": "master", "repo": {"full_name": setup.REPOSITORY}}}]
        code, report = self.run_setup(gh, "--apply", "--delete-master")
        self.assertEqual(code, 1)
        self.assertIn("source branch", report["error"])
        self.assertEqual(gh.mutations, 0)

    def test_fork_dev_is_never_promoted_automatically(self):
        with self.assertRaises(setup.SetupError):
            setup.legacy_pr_target({"head": {"ref": "dev", "repo": {"full_name": "someone/Petri"}}})

    @unittest.skipUnless(shutil.which("git"), "Git is required to test the real atomic lease protocol")
    def test_real_local_remote_lease_rejects_new_tip_and_deletes_only_expected_tip(self):
        # This fixture proves Git's CAS semantics using only temporary local
        # repositories. The production transport still accepts only github.com.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hooks = root / "empty-hooks"
            hooks.mkdir()
            remote, work, empty = (root / name for name in ("remote.git", "work", "empty.git"))
            def git(*args, success=True):
                command = ["git", "-c", "init.templateDir=", "-c", f"core.hooksPath={hooks}", *map(str, args)]
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode == 0, success)
                return result.stdout.strip()
            git("init", "--bare", remote)
            git("init", work)
            git("init", "--bare", empty)
            git("-C", work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "first")
            first = git("-C", work, "rev-parse", "HEAD")
            git("-C", work, "push", remote, "HEAD:refs/heads/master")
            git("--git-dir", remote, "update-ref", "refs/heads/main", first)
            git("--git-dir", remote, "symbolic-ref", "HEAD", "refs/heads/main")
            git("-C", work, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "new tip")
            second = git("-C", work, "rev-parse", "HEAD")
            git("-C", work, "push", remote, "HEAD:refs/heads/master")
            git("--git-dir", remote, "update-ref", "refs/heads/main", second)
            git("--git-dir", empty, "push", f"--force-with-lease=refs/heads/master:{first}", remote, ":refs/heads/master", success=False)
            self.assertEqual(git("--git-dir", remote, "rev-parse", "refs/heads/master"), second)
            git("--git-dir", empty, "push", f"--force-with-lease=refs/heads/master:{second}", remote, ":refs/heads/master")
            git("--git-dir", remote, "show-ref", "--verify", "refs/heads/master", success=False)


if __name__ == "__main__":
    unittest.main()
