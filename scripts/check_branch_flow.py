#!/usr/bin/env python3
"""Validate PR routing: working branches -> dev -> main; main -> dev sync.

This is a CI check, not an enabled GitHub branch protection rule. It performs
no network requests, credentials lookup, Git operations, or repository writes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

REPOSITORY = "QahNaaRlN/Petri"
WORK_PREFIXES = ("feat/", "fix/", "docs/", "chore/")


def is_project_repository(value: object) -> bool:
    # GitHub repository names are case-insensitive; branch refs are not.
    return isinstance(value, str) and value.isascii() and value.lower() == REPOSITORY.lower()


def validate_event(event_name: str, payload: dict) -> str:
    if event_name in ("push", "workflow_dispatch"):
        return "No pull-request routing to validate for this event."
    if event_name != "pull_request":
        raise ValueError(f"Unsupported event: {event_name}")
    if not isinstance(payload, dict):
        raise ValueError("Invalid event payload")
    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        raise ValueError("Pull-request event is missing pull_request")
    base = pr.get("base", {})
    head = pr.get("head", {})
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise ValueError("Invalid branch metadata")
    base_repo, head_repo = base.get("repo"), head.get("repo")
    if not isinstance(base_repo, dict) or not is_project_repository(base_repo.get("full_name")):
        raise ValueError("Unexpected base repository")
    if not isinstance(head_repo, dict) or not isinstance(head_repo.get("full_name"), str):
        raise ValueError("Missing source repository identity")
    base_ref, head_ref = base.get("ref"), head.get("ref")
    if not isinstance(base_ref, str) or not isinstance(head_ref, str):
        raise ValueError("Missing branch identity")
    same_repo = is_project_repository(head_repo["full_name"])
    if base_ref == "main":
        if same_repo and head_ref == "dev":
            return "Accepted: same-repository dev -> main promotion."
        raise ValueError("main accepts only a PR from this repository's dev branch; target dev first")
    if base_ref != "dev":
        raise ValueError("PRs must target dev, or promote this repository's dev to main")
    if same_repo and head_ref == "main":
        return "Accepted: same-repository main -> dev synchronization."
    if any(head_ref.startswith(prefix) and len(head_ref) > len(prefix) for prefix in WORK_PREFIXES):
        return "Accepted: working branch -> dev."
    user = pr.get("user") or {}
    if (same_repo and head_ref.startswith("dependabot/")
            and isinstance(user, dict) and user.get("login") == "dependabot[bot]"
            and user.get("type") == "Bot"):
        return "Accepted: Dependabot update -> dev."
    raise ValueError("Use feat/, fix/, docs/ or chore/ branches for development PRs; main -> dev is reserved for same-repository sync")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-name", default=os.environ.get("GITHUB_EVENT_NAME"))
    parser.add_argument("--event-path", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    args = parser.parse_args()
    if not args.event_name or not args.event_path:
        parser.error("provide --event-name and --event-path, or the standard GitHub Actions variables")
    try:
        if args.event_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Event payload exceeds 8 MiB")
        payload = json.loads(args.event_path.read_text(encoding="utf-8"))
        print(validate_event(args.event_name, payload))
        return 0
    except (OSError, ValueError) as error:
        print(f"Branch policy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
