"""Branch-policy regressions: no API calls or GitHub settings are mutated."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("check_branch_flow", Path(__file__).parents[1] / "scripts/check_branch_flow.py")
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


def event(base, head, repository=flow.REPOSITORY, author=None):
    return {"pull_request": {"base": {"ref": base, "repo": {"full_name": flow.REPOSITORY}},
                             "head": {"ref": head, "repo": {"full_name": repository}}, "user": author or {}}}


class BranchFlowTests(unittest.TestCase):
    def test_canonical_repository_casing_preserves_exact_branch_routing(self):
        payload = event("main", "dev", "qahnaarlN/PETRI")
        payload["pull_request"]["base"]["repo"]["full_name"] = "QahNaaRlN/petri"
        self.assertIn("promotion", flow.validate_event("pull_request", payload))
        payload["pull_request"]["head"]["ref"] = "Dev"
        with self.assertRaises(ValueError):
            flow.validate_event("pull_request", payload)
        payload["pull_request"]["head"]["ref"] = "dev"
        payload["pull_request"]["head"]["repo"]["full_name"] = "other/petri"
        with self.assertRaises(ValueError):
            flow.validate_event("pull_request", payload)
        self.assertFalse(flow.is_project_repository("QahNaaRlN/Petri/extra"))
        self.assertFalse(flow.is_project_repository(None))

    def test_local_and_fork_working_branches_target_dev(self):
        for prefix in flow.WORK_PREFIXES:
            for repo in (flow.REPOSITORY, "contributor/Petri"):
                with self.subTest(prefix=prefix, repository=repo):
                    self.assertIn("Accepted", flow.validate_event("pull_request", event("dev", prefix + "change", repo)))

    def test_main_requires_same_repository_dev(self):
        self.assertIn("promotion", flow.validate_event("pull_request", event("main", "dev")))
        for head, repo in (("feat/change", flow.REPOSITORY), ("dev", "other/Petri"), ("main", flow.REPOSITORY)):
            with self.subTest(head=head, repo=repo), self.assertRaises(ValueError):
                flow.validate_event("pull_request", event("main", head, repo))

    def test_reverse_sync_preserves_history_without_rewriting_dev(self):
        self.assertIn("synchronization", flow.validate_event("pull_request", event("dev", "main")))
        with self.assertRaises(ValueError):
            flow.validate_event("pull_request", event("dev", "main", "other/Petri"))

    def test_master_self_pr_and_unknown_routes_fail(self):
        for base, head in (("master", "feat/change"), ("dev", "master"), ("dev", "dev"), ("dev", "unknown"), ("dev", "feat/")):
            with self.subTest(base=base, head=head), self.assertRaises(ValueError):
                flow.validate_event("pull_request", event(base, head))

    def test_dependabot_exception_requires_real_bot_identity_and_same_repo(self):
        author = {"login": "dependabot[bot]", "type": "Bot"}
        self.assertIn("Dependabot", flow.validate_event("pull_request", event("dev", "dependabot/cargo/update", author=author)))
        for repo, user in (("fork/Petri", author), (flow.REPOSITORY, {"login": "contributor", "type": "User"})):
            with self.subTest(repo=repo, user=user), self.assertRaises(ValueError):
                flow.validate_event("pull_request", event("dev", "dependabot/cargo/update", repo, user))
        with self.assertRaises(ValueError):
            flow.validate_event("pull_request", event("main", "dependabot/cargo/update", author=author))

    def test_missing_metadata_is_not_inferred_as_permission(self):
        for payload in ({}, {"pull_request": {}}, {"pull_request": {"base": [], "head": {}}}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                flow.validate_event("pull_request", payload)

    def test_non_pr_ci_events_are_supported_but_unknown_events_fail(self):
        for name in ("push", "workflow_dispatch"):
            self.assertIn("No pull-request", flow.validate_event(name, {}))
        with self.assertRaises(ValueError):
            flow.validate_event("pull_request_target", {})


if __name__ == "__main__":
    unittest.main()
