#!/usr/bin/env python3
"""Conservative GitHub administration bootstrap for QahNaaRlN/Petri.

Default execution only reads settings and prints a plan. --apply is the only
mutation mode; --verify is read-only. Uses an existing gh identity with no
user-provided shell fragments, login flow, token arguments, history rewrites,
or protection bypass. Git invokes one constant gh credential helper for the
conditional deletion transport; its lease flag guards deletion of master only.
Legacy master deletion additionally requires --delete-master and ancestry proof.
Settings are re-read before each write, but the GitHub API offers no transaction
covering this migration: avoid running concurrent administration operations.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

REPOSITORY = "QahNaaRlN/Petri"
GIT_REMOTE = f"https://github.com/{REPOSITORY}.git"
LEASE_DELETE = "GIT_PUSH_LEASE_DELETE"
ACTIONS_APP_ID = 15368
REQUIRED_CONTEXTS = (
    "Build and portable tests (ubuntu-24.04)",
    "Build and portable tests (macos-14)",
    "Build and portable tests (windows-2022)",
    "Native Linux isolation (required; no skipped success)",
    "Dependency vulnerability audit",
)
REPOSITORY_SETTINGS = {
    "default_branch": "main",
    "allow_squash_merge": False,
    "allow_merge_commit": True,
    "allow_rebase_merge": False,
    "allow_auto_merge": False,
    "delete_branch_on_merge": True,
    "allow_update_branch": True,
}


class SetupError(RuntimeError):
    """A safe-to-report error; never contains raw subprocess output or tokens."""


class GitHubError(SetupError):
    def __init__(self, method: str, endpoint: str, status: int | None):
        self.status = status
        detail = f"HTTP {status}" if status else "gh command failed"
        if status in (401, 403):
            detail += (
                "; the configured GitHub identity lacks access or the required "
                "repository Administration / Pull requests permission. "
                "No authorization was requested and no bypass was attempted"
            )
        super().__init__(f"{method} {endpoint}: {detail}")


class GitHub:
    def delete_master_with_lease(self, expected_sha: str) -> None:
        """Git receive-pack atomically checks the old SHA before deleting.

        REST ref DELETE has no expected-old-SHA predicate and is deliberately
        never used. The only shell command is Git's constant gh credential helper;
        neither user input nor credentials are interpolated into that string.
        """
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", expected_sha):
            raise SetupError("invalid expected master SHA for conditional deletion")
        overrides = ("GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
                     "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")
        if any(os.environ.get(key) for key in overrides):
            raise SetupError("Git repository override environment is present; refusing to operate outside the temporary bare repository")
        env = os.environ.copy()  # Preserve runtime proxy/auth-header/guard settings.
        env.update(GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="", SSH_ASKPASS="")
        def run(args: list[str]) -> str:
            try:
                result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=120, env=env)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SetupError("conditional master deletion could not complete; inspect the branch before retrying") from exc
            if result.returncode:
                # Raw output may contain credential/helper/trace data. Never log it.
                raise SetupError("conditional master deletion was rejected or failed; inspect the branch and configured gh permissions before retrying")
            return result.stdout
        with tempfile.TemporaryDirectory(prefix="petri-repository-lease-") as directory:
            root = Path(directory)
            bare = root / "empty.git"
            hooks = root / "empty-hooks"
            hooks.mkdir()
            run(["git", "-c", "init.templateDir=", "init", "--bare", str(bare)])
            git = ["git", "--git-dir", str(bare), "-c", f"core.hooksPath={hooks}",
                   "-c", "core.askPass=", "-c", "credential.helper=",
                   "-c", "credential.helper=!gh auth git-credential"]
            run(git + ["remote", "add", "origin", GIT_REMOTE])
            urls = run(git + ["remote", "get-url", "--push", "--all", "origin"]).splitlines()
            if urls != [GIT_REMOTE]:
                raise SetupError("Git push URL was rewritten or ambiguous; refusing conditional deletion")
            run(git + ["push", f"--force-with-lease=refs/heads/master:{expected_sha}",
                       "origin", ":refs/heads/master"])

    def call(self, method: str, endpoint: str, payload: dict | None = None,
             *, optional: bool = False, paginate: bool = False) -> Any:
        args = ["gh", "api", "--method", method, endpoint,
                "--hostname", "github.com",
                "--header", "Accept: application/vnd.github+json",
                "--header", "X-GitHub-Api-Version: 2022-11-28"]
        if paginate:
            args.append("--paginate")
        if payload is not None:
            args.extend(["--input", "-"])
        try:
            completed = subprocess.run(
                args, input=json.dumps(payload) if payload is not None else None,
                capture_output=True, text=True, check=False, timeout=120,
            )
        except FileNotFoundError as exc:
            raise SetupError("GitHub CLI (gh) is not installed; no changes were made") from exc
        except subprocess.TimeoutExpired as exc:
            raise SetupError(f"{method} {endpoint}: gh timed out; inspect GitHub before retrying") from exc
        except OSError as exc:
            raise SetupError(f"{method} {endpoint}: unable to execute gh") from exc
        if completed.returncode:
            match = re.search(r"HTTP\s+(\d{3})", completed.stderr or "")
            status = int(match.group(1)) if match else None
            if optional and status == 404:
                return None
            raise GitHubError(method, endpoint, status)
        try:
            if paginate:
                # Older gh releases emit one JSON document per page and have no
                # --slurp flag. Decode documents, never split on braces/newlines.
                decoder = json.JSONDecoder()
                pages, position = [], 0
                output = completed.stdout
                while position < len(output):
                    if output[position].isspace():
                        position += 1
                        continue
                    page, position = decoder.raw_decode(output, position)
                    pages.append(page)
                return pages
            return json.loads(completed.stdout) if completed.stdout.strip() else None
        except json.JSONDecodeError as exc:
            raise SetupError(f"{method} {endpoint}: invalid JSON response") from exc

    def pages(self, endpoint: str) -> list[dict]:
        pages = self.call("GET", endpoint, paginate=True)
        if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
            raise SetupError(f"GET {endpoint}: expected paginated JSON arrays")
        result = [item for page in pages for item in page]
        if any(not isinstance(item, dict) for item in result):
            raise SetupError(f"GET {endpoint}: invalid array item")
        return result


def parse_contexts(protection: dict | None) -> dict[str, int | None]:
    """Parse exact check names and provenance; never split names on punctuation."""
    checks = (protection or {}).get("required_status_checks")
    if checks is None:
        return {}
    if not isinstance(checks, dict):
        raise SetupError("invalid required_status_checks response")
    contexts = checks.get("contexts", [])
    bound = checks.get("checks", [])
    if not isinstance(contexts, list) or any(not isinstance(name, str) for name in contexts):
        raise SetupError("invalid status-check contexts")
    if len(contexts) != len(set(contexts)):
        raise SetupError("duplicate status-check context")
    if not isinstance(bound, list):
        raise SetupError("invalid status-check bindings")
    result = {}
    for item in bound:
        if not isinstance(item, dict) or not isinstance(item.get("context"), str):
            raise SetupError("invalid status-check binding")
        name = item["context"]
        app_id = item.get("app_id")
        if app_id is not None and (not isinstance(app_id, int) or isinstance(app_id, bool)):
            raise SetupError("invalid status-check app_id")
        if name in result:
            raise SetupError("duplicate status-check binding")
        result[name] = app_id
    if bound and contexts and set(contexts) != set(result):
        raise SetupError("status-check contexts and bindings disagree")
    if not bound:
        result = {name: None for name in contexts}
    return result


def enabled(protection: dict | None, key: str) -> bool:
    value = (protection or {}).get(key)
    return isinstance(value, dict) and value.get("enabled") is True


def protection_payload() -> dict:
    return {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": name, "app_id": ACTIONS_APP_ID} for name in REQUIRED_CONTEXTS],
        },
        "enforce_admins": True,
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            "required_approving_review_count": 0,
            "require_last_push_approval": False,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "restrictions": None,
        "required_linear_history": False,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_conversation_resolution": True,
        "block_creations": False,
        "lock_branch": False,
        "allow_fork_syncing": False,
    }


def protection_issues(protection: dict | None, branch: str = "main") -> list[str]:
    if protection is None:
        return [f"{branch} has no branch protection"]
    issues = []
    checks = parse_contexts(protection)
    if checks != {name: ACTIONS_APP_ID for name in REQUIRED_CONTEXTS}:
        issues.append(f"{branch} must require exactly the five CI contexts bound to GitHub Actions app_id 15368")
    if (protection.get("required_status_checks") or {}).get("strict") is not True:
        issues.append(f"{branch} must require strict/up-to-date status checks")
    for key in ("enforce_admins", "required_conversation_resolution"):
        if not enabled(protection, key):
            issues.append(f"{branch} must enable {key}")
    for key in ("allow_force_pushes", "allow_deletions", "required_linear_history"):
        # Missing booleans are not accepted as evidence of disabled settings.
        if not isinstance(protection.get(key), dict) or protection[key].get("enabled") is not False:
            issues.append(f"{branch} must disable {key}")
    if enabled(protection, "lock_branch"):
        issues.append(f"{branch} is locked read-only; repository administration requires manual review")
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        issues.append(f"{branch} must require pull requests")
    else:
        for key, desired in (("dismiss_stale_reviews", True), ("require_code_owner_reviews", False),
                             ("required_approving_review_count", 0), ("require_last_push_approval", False)):
            actual = reviews.get(key)
            if type(actual) is not type(desired) or actual != desired:
                issues.append(f"{branch} pull-request setting {key} must be {desired}")
        bypass = reviews.get("bypass_pull_request_allowances") or {}
        if not isinstance(bypass, dict):
            raise SetupError("invalid pull-request bypass allowances")
        if any(bypass.get(key) for key in ("users", "teams", "apps")):
            issues.append(f"{branch} must not allow specified users, teams or apps to bypass pull requests")
    return issues


@dataclass
class Snapshot:
    repository: dict
    main: dict | None
    master: dict | None
    dev: dict | None
    dev_protection: dict | None
    comparison: dict | None
    protection: dict | None
    protection_branch: str | None
    rulesets: list[dict]
    legacy_prs: list[dict]
    master_head_prs: list[dict]

    def safe_report(self) -> dict:
        return {
            "repository": REPOSITORY,
            "settings": {key: self.repository.get(key) for key in REPOSITORY_SETTINGS},
            "main_sha": (self.main or {}).get("commit", {}).get("sha"),
            "master_sha": (self.master or {}).get("commit", {}).get("sha"),
            "dev_sha": (self.dev or {}).get("commit", {}).get("sha"),
            "dev_protection_issues": protection_issues(self.dev_protection, "dev"),
            "dev_checks": parse_contexts(self.dev_protection),
            "dev_required_signatures_enabled": enabled(self.dev_protection, "required_signatures"),
            "master_ancestry_status": (self.comparison or {}).get("status"),
            "protection_branch": self.protection_branch,
            "protection_issues": protection_issues(self.protection),
            "checks": parse_contexts(self.protection),
            "active_ruleset_ids": [rule.get("id") for rule in self.rulesets if rule.get("enforcement") != "disabled"],
            "required_signatures_enabled": enabled(self.protection, "required_signatures"),
            "open_prs_targeting_master": [pr["number"] for pr in self.legacy_prs],
            "open_prs_from_master": [pr["number"] for pr in self.master_head_prs],
        }


def snapshot(api: GitHub, delete_master: bool = False) -> Snapshot:
    path = f"repos/{REPOSITORY}"
    repository = api.call("GET", path)
    if not isinstance(repository, dict) or repository.get("full_name") != REPOSITORY:
        raise SetupError("GitHub returned a different repository; refusing to continue")
    main = api.call("GET", f"{path}/branches/main", optional=True)
    master = api.call("GET", f"{path}/branches/master", optional=True)
    dev = api.call("GET", f"{path}/branches/dev", optional=True)
    for branch in (main, master, dev):
        if branch is not None:
            sha = branch.get("commit", {}).get("sha")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", sha):
                raise SetupError("GitHub returned invalid branch commit identity")
            if type(branch.get("protected")) is not bool:
                raise SetupError("GitHub returned no authoritative branch protected flag")
    target = "main" if main is not None else "master" if master is not None else None
    selected = main if main is not None else master
    # The public branch endpoint authoritatively reports absence of protection.
    # Avoid an unnecessary Administration-read API call on an unprotected branch.
    protection = (api.call("GET", f"{path}/branches/{target}/protection", optional=True)
                  if selected and selected["protected"] else None)
    if selected and selected["protected"] and protection is None:
        raise SetupError("branch is protected but its policy is unavailable (HTTP 404 or concurrent change); refusing to infer no protection")
    dev_protection = (api.call("GET", f"{path}/branches/dev/protection", optional=True)
                      if dev and dev["protected"] else None)
    if dev and dev["protected"] and dev_protection is None:
        raise SetupError("dev is protected but its policy is unavailable; refusing to infer no protection")
    rulesets = api.pages(f"{path}/rulesets?includes_parents=true&per_page=100")
    legacy_prs = api.pages(f"{path}/pulls?state=open&base=master&per_page=100")
    for pr in legacy_prs:
        number = pr.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number <= 0 or pr.get("base", {}).get("ref") != "master":
            raise SetupError("GitHub returned an invalid legacy pull-request identity")
    comparison = None
    master_head_prs = []
    if delete_master and main is not None and master is not None:
        master_head_prs = api.pages(f"{path}/pulls?state=open&head=QahNaaRlN:master&per_page=100")
        if any(not isinstance(pr.get("number"), int) or pr.get("head", {}).get("ref") != "master"
               or (pr.get("head", {}).get("repo") or {}).get("full_name") != REPOSITORY for pr in master_head_prs):
            raise SetupError("GitHub returned an invalid master-head pull-request identity")
        comparison = api.call("GET", f"{path}/compare/{main['commit']['sha']}...{master['commit']['sha']}")
    return Snapshot(repository, main, master, dev, dev_protection, comparison, protection, target, rulesets, legacy_prs, master_head_prs)


def refuse_weakening(state: Snapshot, branch: str = "main") -> None:
    """Do not replace protections which need a human policy decision to weaken."""
    active_rulesets = [rule for rule in state.rulesets if rule.get("enforcement") != "disabled"]
    if active_rulesets:
        raise SetupError("active/inherited repository rulesets require manual review; no ruleset is modified or bypassed")
    protection = state.dev_protection if branch == "dev" else state.protection
    if not protection:
        return
    existing = parse_contexts(protection)
    extra = set(existing) - set(REQUIRED_CONTEXTS)
    if extra:
        raise SetupError("existing protection requires additional CI checks; refusing to remove them")
    if any(app_id not in (None, -1, ACTIONS_APP_ID) for app_id in existing.values()):
        raise SetupError("existing CI checks are bound to a different app; refusing to replace provenance")
    reviews = protection.get("required_pull_request_reviews") or {}
    if (reviews.get("required_approving_review_count", 0) > 0
            or reviews.get("require_code_owner_reviews")
            or reviews.get("require_last_push_approval")
            or any(reviews.get("dismissal_restrictions", {}).get(key) for key in ("users", "teams", "apps"))):
        raise SetupError("existing review requirements are stronger than the solo-maintainer policy; refusing to weaken them")
    if protection.get("restrictions") is not None or enabled(protection, "lock_branch") or enabled(protection, "block_creations"):
        raise SetupError("existing push/branch restrictions require manual review; refusing to remove them")
    if enabled(protection, "required_linear_history"):
        raise SetupError("existing linear-history requirement is stronger; refusing to weaken it automatically for the main/dev merge-commit profile")


def verification_issues(state: Snapshot, delete_master: bool = False) -> list[str]:
    issues = []
    if state.main is None:
        issues.append("main branch does not exist")
    if state.dev is None:
        issues.append("dev branch does not exist")
    issues.extend(protection_issues(state.dev_protection, "dev"))
    if delete_master and state.master is not None:
        issues.append("legacy master branch still exists")
    for key, desired in REPOSITORY_SETTINGS.items():
        actual = state.repository.get(key)
        if type(actual) is not type(desired) or actual != desired:
            issues.append(f"repository setting {key} must be {desired}")
    if state.protection_branch == "main":
        issues.extend(protection_issues(state.protection))
    else:
        issues.append("main protection has not been verified")
    if state.legacy_prs:
        issues.append("open pull requests still target master")
    if any(rule.get("enforcement") != "disabled" for rule in state.rulesets):
        issues.append("active/inherited repository rulesets require manual verification of the effective branch policy")
    return issues


def legacy_pr_target(pr: dict) -> str:
    head = pr.get("head", {}).get("ref", "")
    if head == "dev":
        if (pr.get("head", {}).get("repo") or {}).get("full_name") != REPOSITORY:
            raise SetupError("fork dev is not the same-repository promotion branch; retarget manually")
        return "main"
    if head.startswith(("feat/", "fix/", "docs/", "chore/")):
        return "dev"
    raise SetupError("legacy pull-request head has no declared branch policy; retarget it manually")


def require_merged_master(state: Snapshot) -> None:
    if state.master_head_prs:
        raise SetupError("open pull requests use master as their source branch; refusing deletion")
    main_sha = (state.main or {}).get("commit", {}).get("sha")
    master_sha = (state.master or {}).get("commit", {}).get("sha")
    comparison = state.comparison
    if (not main_sha or not master_sha or not isinstance(comparison, dict)
            or comparison.get("status") not in ("identical", "behind")
            or type(comparison.get("ahead_by")) is not int or comparison["ahead_by"] != 0
            or comparison.get("base_commit", {}).get("sha") != main_sha
            or comparison.get("merge_base_commit", {}).get("sha") != master_sha):
        raise SetupError("master contains unmerged or unverified commits; refusing deletion")


def require_safe_deletion(api: GitHub, state: Snapshot) -> None:
    issues = verification_issues(state)
    if issues:
        raise SetupError("master deletion prerequisites are not satisfied: " + "; ".join(issues))
    require_merged_master(state)
    # Compare used immutable SHAs. Ensure refs still identify those commits
    # immediately before deleting; no force operation or branch-content rewrite.
    for branch in ("main", "master"):
        current = api.call("GET", f"repos/{REPOSITORY}/branches/{branch}")
        expected = getattr(state, branch)["commit"]["sha"]
        if not isinstance(current, dict) or current.get("commit", {}).get("sha") != expected:
            raise SetupError("branch moved after ancestry verification; refusing master deletion")


def plan(state: Snapshot, delete_master: bool = False) -> list[dict]:
    base = f"repos/{REPOSITORY}"
    actions = []
    if any(rule.get("enforcement") != "disabled" for rule in state.rulesets):
        raise SetupError("active/inherited repository rulesets require manual review; no changes were planned")
    default = state.repository.get("default_branch")
    if default not in ("master", "main"):
        raise SetupError("unexpected default branch; only master-to-main migration is supported")
    if state.main is None:
        if default != "master" or state.master is None:
            raise SetupError("cannot initialize main safely: an existing default master is required")
        actions.append({"method": "POST", "endpoint": f"{base}/branches/master/rename", "payload": {"new_name": "main"}})
    changes = {key: value for key, value in REPOSITORY_SETTINGS.items() if key != "default_branch"
               if type(state.repository.get(key)) is not type(value) or state.repository.get(key) != value}
    if changes:
        actions.append({"method": "PATCH", "endpoint": base, "payload": changes})
    if state.dev is None:
        source = state.main or state.master
        if source is None:
            raise SetupError("cannot create dev without an existing main/master commit")
        actions.append({"method": "POST", "endpoint": f"{base}/git/refs", "payload": {"ref": "refs/heads/dev", "sha": source["commit"]["sha"]}})
    # Preflight both branches before *any* write, so a stronger dev policy does
    # not get discovered only after changing repository/main settings.
    for branch, protection in (("main", state.protection), ("dev", state.dev_protection)):
        if protection_issues(protection, branch):
            refuse_weakening(state, branch)
            actions.append({"method": "PUT", "endpoint": f"{base}/branches/{branch}/protection", "payload": protection_payload()})
    # Apply the merge-commit policy before protecting both long-lived branches.
    # Move the default only *after* protection succeeds, so a partial failure leaves
    # the previous default intact. A rename already migrates the default itself.
    if state.main is not None and default != "main":
        actions.append({"method": "PATCH", "endpoint": base, "payload": {"default_branch": "main"}})
    for pr in sorted(state.legacy_prs, key=lambda item: item["number"]):
        actions.append({"method": "PATCH", "endpoint": f"{base}/pulls/{pr['number']}", "payload": {"base": legacy_pr_target(pr)}})
    if delete_master and state.master is not None and state.main is not None:
        require_merged_master(state)
        actions.append({"method": LEASE_DELETE, "endpoint": GIT_REMOTE,
                        "payload": {"ref": "refs/heads/master", "expected_old_sha": state.master["commit"]["sha"]}})
    return actions


def save_report(path: Path | None, report: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", suffix=".tmp", delete=False) as file:
            temp_path = Path(file.name)
            json.dump(report, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def wait_for_master_absence(api: GitHub) -> int | None:
    """Read-only propagation check after a successful lease; never retry writes."""
    for attempt in range(6):
        branch = api.call("GET", f"repos/{REPOSITORY}/branches/master", optional=True)
        if branch is None:
            return attempt + 1
        if attempt < 5:
            time.sleep(0.5)
    return None


def execute(args: argparse.Namespace, api: GitHub | None = None) -> tuple[int, dict]:
    api = api or GitHub()
    delete_master = args.delete_master
    report = {"repository": REPOSITORY, "mode": args.mode, "status": "reading", "completed": [], "attempted": None,
              "legacy_master_policy": "delete only after ancestry/default/protection checks" if delete_master else "preserved unless renamed into absent main",
              "delete_master_requested": delete_master}
    try:
        state = snapshot(api, delete_master)
        report["before"] = state.safe_report()
        if args.mode == "verify":
            issues = verification_issues(state, delete_master)
            report.update(status="verified" if not issues else "mismatch", issues=issues)
            save_report(args.report, report)
            return (0 if not issues else 1), report
        actions = plan(state, delete_master)
        report.update(status="planned", planned=actions)
        save_report(args.report, report)  # Atomic snapshot/plan before any write.
        if args.mode == "dry-run":
            return 0, report
        preserve_signatures = {branch for branch, protection in (("main", state.protection), ("dev", state.dev_protection)) if enabled(protection, "required_signatures")}
        previous_action = None
        lease_delete_completed = False
        # Re-plan from fresh actual settings before every mutation. This catches
        # stronger policies added since the first snapshot and also accommodates
        # GitHub automatically updating default branch / PR bases on a rename.
        # This is conservative revalidation, not a server-side atomic transaction.
        for _ in range(1000):
            latest = snapshot(api, delete_master)
            report["last_observed"] = latest.safe_report()
            for branch, protection in (("main", latest.protection), ("dev", latest.dev_protection)):
                if branch in preserve_signatures and not enabled(protection, "required_signatures"):
                    raise SetupError(f"previously required commit signatures on {branch} are no longer enabled; manual review required")
                if enabled(protection, "required_signatures"):
                    preserve_signatures.add(branch)
            remaining = plan(latest, delete_master)
            report["remaining"] = remaining
            if not remaining:
                break
            action = remaining[0]
            if action == previous_action:
                raise SetupError("GitHub accepted an update but the actual settings did not change; stopped without retrying")
            if action["method"] == "PATCH" and "/pulls/" in action["endpoint"]:
                pull = api.call("GET", action["endpoint"])
                current_base = pull.get("base", {}).get("ref") if isinstance(pull, dict) else None
                if current_base == action["payload"]["base"]:
                    # A concurrent maintainer/GitHub rename already fulfilled it.
                    report.setdefault("skipped", []).append({"endpoint": action["endpoint"], "reason": "already targets desired branch"})
                    continue
                if current_base != "master":
                    raise SetupError("pull request base changed since the snapshot; refusing to override another target")
            if action["method"] == LEASE_DELETE:
                require_safe_deletion(api, latest)
            report.update(status="applying", attempted=action)
            save_report(args.report, report)
            if action["method"] == LEASE_DELETE:
                api.delete_master_with_lease(action["payload"]["expected_old_sha"])
            else:
                api.call(action["method"], action["endpoint"], action["payload"])
            report["completed"].append(action)
            previous_action = action
            report["attempted"] = None
            save_report(args.report, report)
            if action["method"] == LEASE_DELETE:
                lease_delete_completed = True
                observed_after = wait_for_master_absence(api)
                report["post_delete_verification"] = {
                    "lease_succeeded": True, "reads": observed_after or 6,
                    "api_observed_absence": observed_after is not None,
                }
                if observed_after is None:
                    report.update(status="pending_verification", issues=[
                        "Conditional deletion completed, but the API still reports master after six read-only checks; no second deletion was attempted. Re-run --verify --delete-master later."
                    ])
                    save_report(args.report, report)
                    return 1, report
                # Deletion is the final mutation. Do not re-plan it from a stale
                # branch response; finish with a read-only verification instead.
                break
        else:
            raise SetupError("repository configuration keeps changing; stopped after 1000 operations")
        after = snapshot(api, delete_master)
        report["after"] = after.safe_report()
        issues = verification_issues(after, delete_master)
        for branch, protection in (("main", after.protection), ("dev", after.dev_protection)):
            if branch in preserve_signatures and not enabled(protection, "required_signatures"):
                issues.append(f"previously required commit signatures on {branch} are no longer enabled; manual review required")
        if lease_delete_completed and after.master is not None:
            issues.append("Conditional deletion completed but API visibility is inconsistent; no second deletion was attempted. Re-run --verify --delete-master later.")
            status = "pending_verification"
        else:
            status = "verified" if not issues else "mismatch"
        report.update(status=status, issues=issues)
        save_report(args.report, report)
        return (0 if not issues else 1), report
    except (SetupError, OSError) as exc:
        report.update(status="failed", error=str(exc))
        try:
            save_report(args.report, report)
        except OSError:
            report["report_write_failed"] = True
        return 1, report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", dest="mode", action="store_const", const="dry-run", help="read and print a plan (default)")
    modes.add_argument("--apply", dest="mode", action="store_const", const="apply", help="apply the plan, stop on the first failure, then verify")
    modes.add_argument("--verify", dest="mode", action="store_const", const="verify", help="read settings and fail on any target-policy mismatch")
    result.set_defaults(mode="dry-run")
    result.add_argument("--delete-master", action="store_true", help="also remove legacy master, last, only after ancestry and protection checks")
    result.add_argument("--repo", choices=[REPOSITORY], default=REPOSITORY, help="fixed safety target")
    result.add_argument("--report", type=Path, help="atomically write a sanitized JSON report; no credentials or raw gh responses")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    code, report = execute(args)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if code:
        message = report.get("error")
        if report["status"] == "pending_verification":
            message = report["issues"][-1]
        print(message or "Repository settings do not match the target policy; inspect issues in the report.", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
