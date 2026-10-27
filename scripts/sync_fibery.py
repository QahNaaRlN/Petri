#!/usr/bin/env python3
"""Append explicitly attributed GitHub observations to Petri Human View.

No credential discovery, local Git invocation, PR checkout or arbitrary URL fetch.
This module intentionally never changes Spec, PlanVersion or Decision entities.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

WORKSPACE = "https://krmiftakhov.fibery.io"
REPOSITORY = "QahNaaRlN/petri"
SPACE = "Petri Human View"
SPEC = f"{SPACE}/Spec"
PLAN = f"{SPACE}/PlanVersion"
FACT = f"{SPACE}/WorkNode"
EVIDENCE = f"{SPACE}/Evidence"
NAME = f"{SPACE}/Name"
DESCRIPTION = f"{SPACE}/Description"
PROVENANCE = f"{SPACE}/Происхождение и контекст"
SECRET = "Collaboration~Documents/secret"
ID = "fibery/id"
ALLOWED_WORKFLOWS = {"CI", "Windows native qualification"}
SPEC_RE = r"S-[0-9]{3,6}"
PLAN_RE = r"PV-[0-9]{3,6}-[1-9][0-9]*"
BINDING = re.compile(rf"^\s*Petri:\s*({SPEC_RE})\s*@\s*({PLAN_RE})\s*$", re.M)
SPEC_LINE = re.compile(rf"^\s*Petri-Spec:\s*({SPEC_RE})\s*$", re.M)
PLAN_LINE = re.compile(rf"^\s*Petri-Plan:\s*({PLAN_RE})\s*$", re.M)
SHA = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
SAFE_ERROR_CODE = re.compile(r"[A-Za-z][A-Za-z0-9._/-]{0,159}")


class SyncError(RuntimeError):
    """Safe diagnostic: never contains HTTP headers, event text or credentials."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SyncError("Unexpected HTTP redirect; request stopped")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SyncError("Invalid source timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SyncError("Invalid source timestamp") from error
    if parsed.tzinfo is None:
        raise SyncError("Source timestamp has no timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def fibery_datetime(value: Any) -> str | None:
    """Encode wire DateTime values without changing source-event identities."""
    normalized = timestamp(value)
    if normalized is None:
        return None
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SyncError(f"Invalid {label}")
    return value


def source_sha(value: Any) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise SyncError("Invalid source commit SHA")
    return value.lower()


def check_repository(event: dict[str, Any]) -> None:
    repo = event.get("repository", {})
    if not isinstance(repo, dict) or str(repo.get("full_name", "")).casefold() != REPOSITORY.casefold():
        raise SyncError("Event belongs to a different repository")
    if repo.get("html_url"):
        check_source_url(repo["html_url"], "")


def check_source_url(value: Any, path: str) -> str:
    if not isinstance(value, str):
        raise SyncError("Invalid source URL")
    url = urlsplit(value)
    expected_path = "/" + REPOSITORY + path
    if (url.scheme != "https" or url.netloc != "github.com" or url.username or url.password
            or url.query or url.fragment or url.path.rstrip("/").casefold() != expected_path.casefold()):
        raise SyncError("Source URL is outside the selected repository")
    return "https://github.com/" + REPOSITORY + path


def bindings(text: str) -> list[tuple[str, str]]:
    if not isinstance(text, str):
        raise SyncError("Invalid annotation text")
    # Examples in comments or fenced code are not active attribution.
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    active, fence = [], None
    for line in text.splitlines():
        if fence is None and (line.startswith("    ") or line.startswith("\t")):
            continue  # Markdown indented code, not an active attribution line.
        match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match[1]
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            active.append(line)
    text = "\n".join(active)
    result = set(BINDING.findall(text))
    specs, plans = SPEC_LINE.findall(text), PLAN_LINE.findall(text)
    if specs or plans:
        if len(specs) != 1 or len(plans) != 1:
            raise SyncError("Use one Petri-Spec/Petri-Plan pair or explicit Petri binding lines")
        result.add((specs[0], plans[0]))
    by_spec: dict[str, str] = {}
    for spec, plan in result:
        if spec in by_spec and by_spec[spec] != plan:
            raise SyncError("One source assigns different plan versions to the same spec")
        by_spec[spec] = plan
    return sorted(result)


def document(*paragraphs: str) -> dict[str, Any]:
    return {"doc": {"type": "doc", "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": str(text)}]}
        for text in paragraphs if text
    ]}, "comments": []}


def document_has_content(value: Any) -> bool:
    if isinstance(value, dict):
        # Keep existing user text, embedded objects, comments and nonempty nodes.
        if value.get("comments"):
            return True
        if value.get("text") or value.get("type") not in (None, "doc", "paragraph", "text"):
            return True
        return any(document_has_content(v) for k, v in value.items() if k in {"doc", "content"})
    if isinstance(value, list):
        return any(document_has_content(v) for v in value)
    return False


@dataclass(frozen=True)
class Observation:
    identity: str
    name: str
    url: str
    sha: str
    occurred_at: str | None
    kind: str
    status: str
    state: str
    conclusion: str
    mappings: tuple[tuple[str, str], ...]
    source: str


class JsonHTTP:
    def __init__(self):
        self.opener = build_opener(NoRedirects())

    def request(self, url: str, token: str, method: str = "GET", body: Any = None,
                github: bool = False) -> Any:
        headers = {"Accept": "application/vnd.github+json" if github else "application/json",
                   "Authorization": ("Bearer " if github else "Token ") + token,
                   "User-Agent": "petri-human-view-sync/1"}
        if github:
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise SyncError("Remote response exceeds the size limit")
        except HTTPError as error:
            raise SyncError(f"{'GitHub' if github else 'Fibery'} HTTP {error.code}") from None
        except (URLError, TimeoutError, OSError) as error:
            raise SyncError(f"{'GitHub' if github else 'Fibery'} network request failed") from None
        try:
            return json.loads(raw) if raw else None
        except (UnicodeError, ValueError):
            raise SyncError("Remote response is not valid JSON") from None


class GitHub:
    def __init__(self, token: str, transport: JsonHTTP | None = None):
        self.token = token
        self.transport = transport or JsonHTTP()

    def get(self, path: str) -> Any:
        if not path.startswith(f"/repos/{REPOSITORY}/") or ".." in path or "?" in path:
            raise SyncError("Unsupported GitHub API path")
        return self.transport.request("https://api.github.com" + path, self.token, github=True)

    def pull(self, number: int) -> dict[str, Any]:
        positive_int(number, "pull request number")
        row = self.get(f"/repos/{REPOSITORY}/pulls/{number}")
        if not isinstance(row, dict) or row.get("number") != number:
            raise SyncError("GitHub pull request response does not match request")
        check_source_url(row.get("html_url"), f"/pull/{number}")
        return row


def event_identity(event_name: str, event: dict[str, Any]) -> str:
    """Stable lock key, shared by duplicate deliveries/retries of one source event."""
    check_repository(event)
    if event_name == "workflow_run":
        run = event.get("workflow_run", {})
        return f"run:{positive_int(run.get('id'), 'workflow run id')}:attempt:{positive_int(run.get('run_attempt'), 'workflow run attempt')}"
    if event_name == "pull_request_target":
        pr = event.get("pull_request", {})
        payload = {"number": positive_int(pr.get("number"), "pull request number"),
                   "action": event.get("action"), "updated_at": timestamp(pr.get("updated_at")),
                   "sha": source_sha(pr.get("head", {}).get("sha")),
                   "title": pr.get("title"), "body": pr.get("body")}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]
        return f"pr:{payload['number']}:{digest}"
    return event_name + ":" + hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:24]


def observations(event_name: str, event: dict[str, Any], github: GitHub | None) -> list[Observation]:
    check_repository(event)
    if event_name == "pull_request_target":
        pr = event.get("pull_request", {})
        number = positive_int(pr.get("number"), "pull request number")
        url = check_source_url(pr.get("html_url"), f"/pull/{number}")
        action = event.get("action")
        if action not in {"opened", "reopened", "edited", "synchronize", "closed", "ready_for_review", "converted_to_draft"}:
            return []
        date = timestamp(pr.get("updated_at"))
        if not date:
            raise SyncError("PR event has no updated_at timestamp")
        sha = source_sha(pr.get("head", {}).get("sha"))
        # This is the frozen event payload, never the current PR's updated_at.
        mapped = bindings((pr.get("title") or "") + "\n" + (pr.get("body") or ""))
        if not mapped:
            return []
        conclusion = "merged" if action == "closed" and pr.get("merged") is True else action
        return [Observation(event_identity(event_name, event), f"PR #{number}: {conclusion}", url, sha, date,
                            "source", "NOT_RUN", "recorded", conclusion, tuple(mapped),
                            "GitHub pull_request_target payload; PR metadata observation only")]
    if event_name != "workflow_run":
        return []
    if event.get("action") != "completed":
        return []
    run = event.get("workflow_run", {})
    if run.get("name") not in ALLOWED_WORKFLOWS:
        return []
    if run.get("status") != "completed":
        raise SyncError("Workflow completed event has a noncompleted source status")
    run_id = positive_int(run.get("id"), "workflow run id")
    attempt = positive_int(run.get("run_attempt"), "workflow run attempt")
    url = check_source_url(run.get("html_url"), f"/actions/runs/{run_id}")
    sha = source_sha(run.get("head_sha"))
    conclusion = run.get("conclusion")
    if conclusion not in {"success", "failure", "timed_out", "cancelled", "skipped", "neutral", "stale", "action_required", "startup_failure"}:
        raise SyncError("Unknown completed workflow conclusion")
    verdict = "PASS" if conclusion == "success" else "FAIL" if conclusion in {"failure", "timed_out", "startup_failure"} else "NOT_RUN"
    text = (run.get("head_commit") or {}).get("message") or ""
    mapped = set(bindings(text))
    prs = run.get("pull_requests", [])
    if not isinstance(prs, list) or len(prs) > 100:
        raise SyncError("Invalid workflow pull request associations")
    if prs and github is None:
        raise SyncError("GitHub read credential is required to resolve PR annotations")
    for short_pr in prs:
        pr = github.pull(positive_int(short_pr.get("number"), "associated PR number"))
        mapped.update(bindings((pr.get("title") or "") + "\n" + (pr.get("body") or "")))
    # A workflow-run payload may omit PR associations after merge. Do not guess
    # from branch names or infer a plan from the current Fibery pointer.
    by_spec: dict[str, str] = {}
    for spec, plan in mapped:
        if spec in by_spec and by_spec[spec] != plan:
            raise SyncError("Workflow annotations assign conflicting plan versions")
        by_spec[spec] = plan
    if not mapped:
        return []
    kind = "portable_ci" if run.get("name") == "CI" else "source"
    return [Observation(f"run:{run_id}:attempt:{attempt}", f"{run['name']} · {conclusion} · attempt {attempt}",
                        url, sha, timestamp(run.get("updated_at")), kind, verdict, "completed", conclusion,
                        tuple(sorted(mapped)), "GitHub workflow_run.completed metadata; explicit PR annotation observed at import")]


class Fibery:
    def __init__(self, token: str, transport: JsonHTTP | None = None):
        self.token = token
        self.transport = transport or JsonHTTP()

    def command(self, name: str, args: dict[str, Any]) -> Any:
        result = self.transport.request(WORKSPACE + "/api/commands", self.token, "POST",
                                        [{"command": name, "args": args}])
        if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
            raise SyncError("Invalid Fibery command envelope")
        item = result[0]
        if item.get("success") is not True:
            # Only the bounded machine code is diagnostic. Messages and data can
            # contain input text, headers or secrets and must never be echoed.
            error = item.get("result")
            code = error.get("name") if isinstance(error, dict) else None
            if not isinstance(code, str) or not SAFE_ERROR_CODE.fullmatch(code):
                code = "unknown_error"
            for secret in (self.token, os.getenv("FIBERY_API_TOKEN"), os.getenv("GITHUB_TOKEN")):
                if secret:
                    code = code.replace(secret, "[redacted]")
            raise SyncError("Fibery command failed: " + name + " (" + code + ")")
        return item.get("result")

    def query(self, type_name: str, fields: dict[str, Any], where=None, params=None) -> list[dict[str, Any]]:
        query = {"q/from": type_name, "q/select": fields, "q/limit": 2}
        if where is not None:
            query["q/where"] = where
        args = {"query": query}
        if params:
            args["params"] = params
        rows = self.command("fibery.entity/query", args)
        if not isinstance(rows, list):
            raise SyncError("Fibery query did not return a list")
        return rows

    def unique(self, type_name: str, key_field: str, key: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        rows = self.query(type_name, fields, ["=", [key_field], "$key"], {"$key": key})
        if len(rows) > 1:
            raise SyncError("Duplicate stable key in Fibery; stop for review")
        return rows[0] if rows else None

    def option(self, type_name: str, value: str) -> str:
        rows = self.query(type_name, {"id": [ID]}, ["=", ["enum/name"], "$name"], {"$name": value})
        if len(rows) != 1:
            raise SyncError("Required Fibery enum option is missing or ambiguous")
        return rows[0]["id"]

    def create(self, type_name: str, values: dict[str, Any]) -> str:
        if type_name not in {FACT, EVIDENCE}:
            raise SyncError("Bridge can create only WorkNode or Evidence")
        result = self.command("fibery.entity/create", {"type": type_name, "entity": values})
        if not isinstance(result, dict) or not isinstance(result.get(ID), str):
            raise SyncError("Fibery create returned no entity ID")
        return result[ID]

    def ensure_document(self, secret: str, content: dict[str, Any]) -> bool:
        if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", secret):
            raise SyncError("Invalid Fibery document secret")
        url = WORKSPACE + "/api/documents/" + quote(secret, safe="") + "?format=json"
        current = self.transport.request(url, self.token)
        if not isinstance(current, dict) or "content" not in current:
            raise SyncError("Invalid Fibery document response")
        if document_has_content(current["content"]):
            return False
        self.transport.request(url, self.token, "PUT", {"content": content})
        return True

    def link(self, fact_id: str, evidence_id: str) -> None:
        self.command("fibery.entity/add-collection-items", {
            "type": FACT, "field": f"{SPACE}/Доказательства", "entity": {fact_id: [evidence_id]}})


def projected() -> dict[str, Any]:
    return {"id": [ID], "description": [DESCRIPTION, SECRET], "provenance": [PROVENANCE, SECRET]}


class Sync:
    def __init__(self, client: Fibery, observed_at: str | None = None):
        self.client = client
        self.observed_at = timestamp(observed_at) if observed_at else iso_now()

    def bind(self, spec_key: str, plan_key: str) -> tuple[str, str]:
        spec = self.client.unique(SPEC, f"{SPACE}/Ключ", spec_key, {"id": [ID]})
        plan = self.client.unique(PLAN, f"{SPACE}/Ключ версии", plan_key,
                                  {"id": [ID], "spec": [f"{SPACE}/Спека", ID]})
        if not spec or not plan:
            raise SyncError("Explicit spec or plan binding is not present in Fibery")
        if plan.get("spec") != spec["id"]:
            raise SyncError("Explicit plan belongs to a different spec")
        return spec["id"], plan["id"]

    def run(self, source: Observation) -> dict[str, int]:
        total = {"observations": 0, "entities_created": 0, "documents_filled": 0}
        # Validate every mapping before making any writes for the observation.
        resolved = [(spec, plan, *self.bind(spec, plan)) for spec, plan in source.mappings]
        for spec_key, plan_key, spec_id, plan_id in resolved:
            identity = REPOSITORY.casefold() + ":" + source.identity + ":" + spec_key
            evidence_key = "GH-E:" + identity
            fact_key = "GH-N:" + identity
            ev_fields = projected() | {"url": [f"{SPACE}/URL источника"], "sha": [f"{SPACE}/Commit SHA"],
                                       "status": [f"{SPACE}/Результат проверки", "enum/name"],
                                       "kind": [f"{SPACE}/Вид источника", "enum/name"],
                                       "native": [f"{SPACE}/Наблюдалось нативное исполнение"]}
            ev = self.client.unique(EVIDENCE, f"{SPACE}/Ключ доказательства", evidence_key, ev_fields)
            if not ev:
                ev_id = self.client.create(EVIDENCE, {
                    f"{SPACE}/Ключ доказательства": evidence_key, NAME: source.name,
                    f"{SPACE}/URL источника": source.url, f"{SPACE}/Commit SHA": source.sha,
                    f"{SPACE}/Вид источника": {ID: self.client.option(f"{SPACE}/Вид источника_{EVIDENCE}", source.kind)},
                    f"{SPACE}/Платформа": {ID: self.client.option(f"{SPACE}/Платформа_{EVIDENCE}", "common")},
                    f"{SPACE}/Результат проверки": {ID: self.client.option(f"{SPACE}/Результат проверки_{EVIDENCE}", source.status)},
                    f"{SPACE}/Наблюдалось нативное исполнение": False,
                    f"{SPACE}/Дата проверки": fibery_datetime(self.observed_at),
                })
                total["entities_created"] += 1
                ev = self.client.unique(EVIDENCE, f"{SPACE}/Ключ доказательства", evidence_key, ev_fields)
                if not ev or ev["id"] != ev_id:
                    raise SyncError("Created Evidence not uniquely visible; retry the same event")
            elif (ev.get("url") != source.url or ev.get("sha") != source.sha
                  or ev.get("status") != source.status or ev.get("kind") != source.kind or ev.get("native") is not False):
                raise SyncError("Existing immutable Evidence conflicts with source event")
            fact_fields = projected() | {"spec": [f"{SPACE}/Спека", ID], "plan": [f"{SPACE}/Версия ожиданий на момент работы", ID]}
            fact = self.client.unique(FACT, f"{SPACE}/Ключ узла", fact_key, fact_fields)
            if not fact:
                fact_id = self.client.create(FACT, {
                    f"{SPACE}/Ключ узла": fact_key, NAME: source.name,
                    f"{SPACE}/Спека": {ID: spec_id}, f"{SPACE}/Версия ожиданий на момент работы": {ID: plan_id},
                    f"{SPACE}/Тип факта": {ID: self.client.option(f"{SPACE}/Тип факта_{FACT}", "execution" if source.state == "completed" else "observation")},
                    "workflow/state": {ID: self.client.option(f"workflow/state_{FACT}", source.state)},
                    f"{SPACE}/Когда произошло": fibery_datetime(source.occurred_at),
                })
                total["entities_created"] += 1
                fact = self.client.unique(FACT, f"{SPACE}/Ключ узла", fact_key, fact_fields)
                if not fact or fact["id"] != fact_id:
                    raise SyncError("Created WorkNode not uniquely visible; retry the same event")
            elif fact.get("spec") != spec_id or fact.get("plan") != plan_id:
                raise SyncError("Existing immutable WorkNode has another plan binding")
            context = document(
                "Автоматически импортированное наблюдение GitHub, не человеческая приёмка.",
                "Source: " + source.url, "Commit SHA: " + source.sha,
                "Stable event identity: " + source.identity,
                f"Explicit binding: {spec_key} @ {plan_key}.",
                "Привязка аннотирована явно в источнике и наблюдалась при импорте. Это не доказательство назначения плана на историческую дату работы.",
                "Нативное исполнение и полнота тестов не исследованы этим bridge; workflow PASS не равен квалификации платформы или принятию результата.",
                "Записи Spec, PlanVersion и Decision этим импортом не изменяются.")
            evidence_body = document(source.source, "Workflow/PR metadata outcome: " + source.conclusion,
                                     "Source: " + source.url, "Commit SHA: " + source.sha,
                                     "Статус относится только к metadata указанного workflow/PR. Логи тестов, native reports, trust boundary и acceptance этим событием не доказаны.")
            fact_body = document(source.name, "Source: " + source.url,
                                 "GitHub source metadata updated_at: " + str(source.occurred_at),
                                 "Event identity: " + source.identity,
                                 "PR/CI событие зафиксировано. Причинные и хронологические связи с другими действиями не выводятся автоматически.")
            for row, body in [(ev, evidence_body), (fact, fact_body)]:
                for key, content in [("description", body), ("provenance", context)]:
                    total["documents_filled"] += int(self.client.ensure_document(row[key], content))
            self.client.link(fact["id"], ev["id"])
            total["observations"] += 1
        return total


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", default=os.getenv("GITHUB_EVENT_PATH"))
    parser.add_argument("--event-name", default=os.getenv("GITHUB_EVENT_NAME"))
    parser.add_argument("--dry-run", action="store_true", help="Parse event and annotations without Fibery writes")
    parser.add_argument("--check-config", action="store_true", help="Read-only check of Fibery bindings and required enum options")
    parser.add_argument("--concurrency-key", action="store_true", help="Output a safe Actions lock_key without network calls")
    args = parser.parse_args(argv)
    try:
        if (args.check_config or args.event_name == "workflow_dispatch") and not args.concurrency_key:
            token = os.getenv("FIBERY_API_TOKEN")
            if not token:
                raise SyncError("FIBERY_API_TOKEN is not configured in repository Actions secrets")
            client = Fibery(token)
            for target, value in [(f"{SPACE}/Вид источника_{EVIDENCE}", "source"),
                                  (f"{SPACE}/Вид источника_{EVIDENCE}", "portable_ci"),
                                  (f"{SPACE}/Результат проверки_{EVIDENCE}", "PASS"),
                                  (f"{SPACE}/Результат проверки_{EVIDENCE}", "FAIL"),
                                  (f"{SPACE}/Результат проверки_{EVIDENCE}", "NOT_RUN"),
                                  (f"{SPACE}/Платформа_{EVIDENCE}", "common"),
                                  (f"{SPACE}/Тип факта_{FACT}", "execution"),
                                  (f"{SPACE}/Тип факта_{FACT}", "observation"),
                                  (f"workflow/state_{FACT}", "completed"),
                                  (f"workflow/state_{FACT}", "recorded")]:
                client.option(target, value)
            client.query(SPEC, {"id": [ID], "key": [f"{SPACE}/Ключ"]})
            client.query(PLAN, {"id": [ID], "key": [f"{SPACE}/Ключ версии"], "spec": [f"{SPACE}/Спека", ID]})
            print(json.dumps({"status": "read_only_configuration_check_passed", "writes": 0}))
            return 0
        if not args.event:
            raise SyncError("GitHub event file is missing")
        raw = Path(args.event).read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise SyncError("GitHub event exceeds size limit")
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise SyncError("GitHub event must be an object")
        if args.concurrency_key:
            identity = event_identity(args.event_name, event)
            print("lock_key=" + hashlib.sha256(identity.encode()).hexdigest())
            return 0
        gh_token = os.getenv("GITHUB_TOKEN", "")
        records = observations(args.event_name, event, GitHub(gh_token) if gh_token else None)
        if args.dry_run:
            print(json.dumps({"status": "dry_run", "observations": len(records),
                              "bindings": sum(len(r.mappings) for r in records), "writes": 0}))
            return 0
        if not records:
            print(json.dumps({"status": "skipped_no_explicit_binding_or_supported_event", "writes": 0}))
            return 0
        token = os.getenv("FIBERY_API_TOKEN")
        if not token:
            raise SyncError("FIBERY_API_TOKEN is not configured in repository Actions secrets")
        sync = Sync(Fibery(token))
        totals = {"observations": 0, "entities_created": 0, "documents_filled": 0}
        for record in records:
            for key, count in sync.run(record).items():
                totals[key] += count
        print(json.dumps({"status": "synced", **totals}))
        return 0
    except (SyncError, ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        # Suppress event-derived strings and exception reprs. Network/service
        # diagnostics above are deliberately constructed without payload bodies.
        safe = str(error) if isinstance(error, SyncError) else "Invalid input or incomplete API response"
        for token in [os.getenv("FIBERY_API_TOKEN"), os.getenv("GITHUB_TOKEN")]:
            if token:
                safe = safe.replace(token, "[redacted]")
        print("Petri sync failed: " + safe, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
