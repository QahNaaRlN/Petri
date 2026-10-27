import contextlib
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

# Works beside the module during preparation and in tests/ after repository install.
SOURCE = Path(__file__).with_name("fibery_sync.py")
if not SOURCE.exists():
    SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "sync_fibery.py"
import sys
spec = importlib.util.spec_from_file_location("petri_fibery_sync", SOURCE)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

SHA = "a" * 40
DATE = "2026-10-27T10:00:00Z"


def pull_event(body="Petri: S-001 @ PV-001-2", action="opened"):
    return {"repository": {"full_name": m.REPOSITORY,
                           "html_url": "https://github.com/" + m.REPOSITORY},
            "action": action,
            "pull_request": {"number": 17, "html_url": "https://github.com/" + m.REPOSITORY + "/pull/17",
                             "head": {"sha": SHA}, "title": "Example", "body": body,
                             "updated_at": DATE, "merged": action == "closed"}}


def workflow_event(conclusion="success", attempt=1):
    return {"repository": {"full_name": m.REPOSITORY}, "action": "completed",
            "workflow_run": {"name": "CI", "id": 123, "run_attempt": attempt,
                             "status": "completed", "conclusion": conclusion,
                             "html_url": "https://github.com/" + m.REPOSITORY + "/actions/runs/123",
                             "head_sha": SHA, "updated_at": DATE,
                             "head_commit": {"message": "Petri: S-001 @ PV-001-2"}, "pull_requests": []}}


class MemoryFibery:
    def __init__(self):
        self.rows = {m.SPEC: [{"id": "spec-1", "key": "S-001"}, {"id": "spec-2", "key": "S-002"}],
                     m.PLAN: [{"id": "plan-1", "key": "PV-001-2", "spec": "spec-1"},
                              {"id": "plan-2", "key": "PV-002-1", "spec": "spec-2"}],
                     m.FACT: [], m.EVIDENCE: []}
        self.documents = {}
        self.links = set()
        self.created_types = []
        self.fail_fact_once = False
        self.fail_document_once = False
        self.failure_triggered = False

    def unique(self, type_name, key_field, key, fields):
        rows = [row for row in self.rows[type_name] if row["key"] == key]
        if len(rows) > 1:
            raise m.SyncError("Duplicate stable key in Fibery; stop for review")
        return deepcopy(rows[0]) if rows else None

    def option(self, type_name, value):
        return "option:" + value

    def create(self, type_name, values):
        if type_name == m.FACT and self.fail_fact_once and not self.failure_triggered:
            self.failure_triggered = True
            raise m.SyncError("simulated interrupted create")
        self.created_types.append(type_name)
        row_id = "entity-" + str(len(self.created_types))
        desc = "document-" + row_id
        provenance = "provenance-" + row_id
        if type_name == m.EVIDENCE:
            row = {"id": row_id, "key": values[f"{m.SPACE}/Ключ доказательства"],
                   "url": values[f"{m.SPACE}/URL источника"], "sha": values[f"{m.SPACE}/Commit SHA"],
                   "status": values[f"{m.SPACE}/Результат проверки"][m.ID].removeprefix("option:"),
                   "kind": values[f"{m.SPACE}/Вид источника"][m.ID].removeprefix("option:"),
                   "native": values[f"{m.SPACE}/Наблюдалось нативное исполнение"]}
        elif type_name == m.FACT:
            row = {"id": row_id, "key": values[f"{m.SPACE}/Ключ узла"],
                   "spec": values[f"{m.SPACE}/Спека"][m.ID],
                   "plan": values[f"{m.SPACE}/Версия ожиданий на момент работы"][m.ID]}
        else:
            raise AssertionError("Unexpected mutation: " + type_name)
        row |= {"description": desc, "provenance": provenance, "values": deepcopy(values)}
        self.rows[type_name].append(row)
        self.documents[desc] = m.document()
        self.documents[provenance] = m.document()
        return row_id

    def ensure_document(self, secret, content):
        if self.fail_document_once and not self.failure_triggered and len([v for v in self.documents.values() if m.document_has_content(v)]) >= 2:
            self.failure_triggered = True
            raise m.SyncError("simulated document interruption")
        if m.document_has_content(self.documents[secret]):
            return False
        self.documents[secret] = deepcopy(content)
        return True

    def link(self, fact_id, evidence_id):
        self.links.add((fact_id, evidence_id))


class BindingTests(unittest.TestCase):
    def test_explicit_bindings_and_pair(self):
        self.assertEqual(m.bindings("Petri: S-001 @ PV-001-2\nPetri: S-002 @ PV-002-1"),
                         [("S-001", "PV-001-2"), ("S-002", "PV-002-1")])
        self.assertEqual(m.bindings("Petri-Spec: S-001\nPetri-Plan: PV-001-2"), [("S-001", "PV-001-2")])

    def test_examples_comments_and_mentions_do_not_assign_a_plan(self):
        text = "S-001\n[PV-001-2]\n```text\nPetri: S-001 @ PV-001-2\n```\n<!--\nPetri: S-002 @ PV-002-1\n-->\n> Petri: S-001 @ PV-001-2\n    Petri: S-001 @ PV-001-2\n\tPetri: S-002 @ PV-002-1"
        self.assertEqual(m.bindings(text), [])

    def test_up_to_three_spaces_are_active_but_indented_code_is_not(self):
        text = "    Petri: S-002 @ PV-002-1\n   Petri: S-001 @ PV-001-2"
        self.assertEqual(m.bindings(text), [("S-001", "PV-001-2")])

    def test_ambiguous_mapping_stops(self):
        with self.assertRaises(m.SyncError):
            m.bindings("Petri: S-001 @ PV-001-1\nPetri: S-001 @ PV-001-2")
        with self.assertRaises(m.SyncError):
            m.bindings("Petri-Spec: S-001")


class EventTests(unittest.TestCase):
    def test_event_lock_serializes_duplicates_and_separates_distinct_edits(self):
        event = pull_event(action="edited")
        first = m.event_identity("pull_request_target", event)
        self.assertEqual(first, m.event_identity("pull_request_target", deepcopy(event)))
        event["pull_request"]["body"] += "\nChanged"
        self.assertNotEqual(first, m.event_identity("pull_request_target", event))
        run = workflow_event("success", attempt=1)
        self.assertEqual(m.event_identity("workflow_run", run),
                         m.event_identity("workflow_run", workflow_event("failure", attempt=1)))
        self.assertNotEqual(m.event_identity("workflow_run", run),
                            m.event_identity("workflow_run", workflow_event(attempt=2)))

    def test_ci_conclusion_is_scoped_and_reruns_have_new_identity(self):
        outcomes = {"success": "PASS", "failure": "FAIL", "timed_out": "FAIL", "cancelled": "NOT_RUN", "skipped": "NOT_RUN", "action_required": "NOT_RUN"}
        for outcome, expected in outcomes.items():
            result = m.observations("workflow_run", workflow_event(outcome), None)[0]
            self.assertEqual(result.status, expected)
            self.assertEqual(result.state, "completed")
        first = m.observations("workflow_run", workflow_event(attempt=1), None)[0]
        second = m.observations("workflow_run", workflow_event(attempt=2), None)[0]
        self.assertNotEqual(first.identity, second.identity)

    def test_merge_is_metadata_not_acceptance_or_test_pass(self):
        observation = m.observations("pull_request_target", pull_event(action="closed"), None)[0]
        self.assertEqual(observation.conclusion, "merged")
        self.assertEqual(observation.status, "NOT_RUN")
        self.assertEqual(observation.state, "recorded")

    def test_source_ownership_and_url_checked(self):
        for field, value in [("full_name", "attacker/petri"), ("html_url", "https://github.com.evil.test/QahNaaRlN/petri")]:
            event = pull_event()
            event["repository"][field] = value
            with self.assertRaises(m.SyncError):
                m.observations("pull_request_target", event, None)
        event = pull_event()
        event["pull_request"]["html_url"] = "https://github.com/attacker/petri/pull/17"
        with self.assertRaises(m.SyncError):
            m.observations("pull_request_target", event, None)

    def test_no_marker_does_not_guess_current_plan(self):
        self.assertEqual(m.observations("pull_request_target", pull_event("S-001 is discussed"), None), [])

    def test_pr_edited_with_same_timestamp_keeps_distinct_source_revision(self):
        first = m.observations("pull_request_target", pull_event(action="edited"), None)[0]
        event = pull_event(action="edited")
        event["pull_request"]["body"] += "\nAnother observation"
        second = m.observations("pull_request_target", event, None)[0]
        self.assertNotEqual(first.identity, second.identity)

    def test_workflow_pr_annotations_fetched_only_through_fixed_api(self):
        event = workflow_event()
        event["workflow_run"]["head_commit"] = None
        event["workflow_run"]["pull_requests"] = [{"number": 17, "url": "https://evil.test/ignored"}]
        class GH:
            def pull(self, number):
                self.number = number
                return pull_event()["pull_request"]
        gh = GH()
        result = m.observations("workflow_run", event, gh)
        self.assertEqual(gh.number, 17)
        self.assertEqual(result[0].mappings, (("S-001", "PV-001-2"),))


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.db = MemoryFibery()
        self.observation = m.observations("workflow_run", workflow_event(), None)[0]
        self.sync = m.Sync(self.db, DATE)

    def test_retry_is_idempotent_and_does_not_promote_spec(self):
        before = deepcopy((self.db.rows[m.SPEC], self.db.rows[m.PLAN]))
        self.assertEqual(self.sync.run(self.observation)["entities_created"], 2)
        self.assertEqual(self.sync.run(self.observation)["entities_created"], 0)
        self.assertEqual(len(self.db.links), 1)
        self.assertEqual((self.db.rows[m.SPEC], self.db.rows[m.PLAN]), before)
        self.assertEqual(set(self.db.created_types), {m.FACT, m.EVIDENCE})
        self.assertIs(self.db.rows[m.EVIDENCE][0]["native"], False)

    def test_partial_creation_retry_repairs_instead_of_duplicate(self):
        self.db.fail_fact_once = True
        with self.assertRaises(m.SyncError):
            self.sync.run(self.observation)
        self.assertEqual(len(self.db.rows[m.EVIDENCE]), 1)
        self.assertEqual(len(self.db.rows[m.FACT]), 0)
        self.sync.run(self.observation)
        self.assertEqual(len(self.db.rows[m.EVIDENCE]), 1)
        self.assertEqual(len(self.db.rows[m.FACT]), 1)
        self.assertEqual(len(self.db.links), 1)

    def test_partial_documents_retry_preserves_human_edits(self):
        self.db.fail_document_once = True
        with self.assertRaises(m.SyncError):
            self.sync.run(self.observation)
        first_secret = self.db.rows[m.EVIDENCE][0]["description"]
        human = m.document("Human clarification")
        self.db.documents[first_secret] = human
        self.sync.run(self.observation)
        self.assertEqual(self.db.documents[first_secret], human)
        self.assertTrue(all(m.document_has_content(v) for v in self.db.documents.values()))
        self.assertEqual(len(self.db.links), 1)

    def test_unknown_or_wrong_plan_fails_before_writes(self):
        self.db.rows[m.PLAN][0]["spec"] = "spec-2"
        with self.assertRaises(m.SyncError):
            self.sync.run(self.observation)
        self.assertEqual(self.db.created_types, [])

    def test_all_multi_spec_bindings_validated_before_any_write(self):
        observation = m.observations("pull_request_target", pull_event("Petri: S-001 @ PV-001-2\nPetri: S-003 @ PV-003-1"), None)[0]
        with self.assertRaises(m.SyncError):
            self.sync.run(observation)
        self.assertEqual(self.db.created_types, [])

    def test_immutable_verdict_conflict_does_not_rewrite_evidence(self):
        self.sync.run(self.observation)
        original = deepcopy(self.db.rows[m.EVIDENCE])
        changed = m.observations("workflow_run", workflow_event("failure"), None)[0]
        with self.assertRaises(m.SyncError):
            self.sync.run(changed)
        self.assertEqual(self.db.rows[m.EVIDENCE], original)

    def test_nonempty_embedded_document_or_comments_are_preserved(self):
        self.assertTrue(m.document_has_content({"doc": {"type": "doc", "content": [{"type": "image"}]}, "comments": []}))
        self.assertTrue(m.document_has_content({"doc": {"type": "doc", "content": []}, "comments": [{"text": "remark"}]}))
        self.assertFalse(m.document_has_content(m.document()))


class WireTests(unittest.TestCase):
    def test_datetime_wire_format_is_utc_milliseconds_and_preserves_none(self):
        cases = [
            ("2026-10-27T13:48:33.438122Z", "2026-10-27T13:48:33.438Z"),
            ("2026-10-27T15:48:33.438122+02:00", "2026-10-27T13:48:33.438Z"),
            ("2026-10-27T10:00:00Z", "2026-10-27T10:00:00.000Z"),
            ("2026-10-27T10:00:00.4Z", "2026-10-27T10:00:00.400Z"),
            (None, None),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(m.fibery_datetime(source), expected)

    def test_wire_datetime_fix_does_not_change_existing_pr_event_key(self):
        event = pull_event()
        self.assertEqual(m.event_identity("pull_request_target", event), "pr:17:19d18fa508466adb158b9dac")
        db = MemoryFibery()
        observation = m.observations("pull_request_target", event, None)[0]
        sync = m.Sync(db, observed_at="2026-10-27T13:48:33.438122Z")
        sync.run(observation)
        self.assertEqual(db.rows[m.EVIDENCE][0]["values"][f"{m.SPACE}/Дата проверки"],
                         "2026-10-27T13:48:33.438Z")
        self.assertEqual(db.rows[m.FACT][0]["values"][f"{m.SPACE}/Когда произошло"],
                         "2026-10-27T10:00:00.000Z")
        sync.run(observation)
        self.assertEqual(len(db.rows[m.EVIDENCE]), 1)
        self.assertEqual(len(db.rows[m.FACT]), 1)

    def test_api_error_exposes_only_bounded_machine_code(self):
        class Transport:
            def __init__(self, name):
                self.name = name
            def request(self, *args):
                return [{"success": False, "result": {"name": self.name,
                         "message": "PRIVATE-MESSAGE token-123", "data": {"headers": "PRIVATE-DATA"}}}]
        for code, expected in [("entity.error/invalid-date-time", "entity.error/invalid-date-time"),
                               ("bad code\nPRIVATE", "unknown_error"),
                               ("x" * 161, "unknown_error"),
                               (None, "unknown_error")]:
            with self.subTest(code=code):
                with self.assertRaises(m.SyncError) as raised:
                    m.Fibery("token-123", Transport(code)).create(m.EVIDENCE, {})
                message = str(raised.exception)
                self.assertIn(expected, message)
                for private in ["PRIVATE-MESSAGE", "PRIVATE-DATA", "token-123"]:
                    self.assertNotIn(private, message)

    def test_api_error_machine_code_redacts_credential_if_reflected(self):
        class Transport:
            def request(self, *args):
                return [{"success": False, "result": {"name": "entity.error/secret-token"}}]
        with self.assertRaises(m.SyncError) as raised:
            m.Fibery("secret-token", Transport()).create(m.EVIDENCE, {})
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertIn("[redacted]", str(raised.exception))

    def test_lock_cli_needs_no_secret_or_api_and_outputs_only_safe_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps(pull_event()))
            output = io.StringIO()
            with patch.dict("os.environ", {}, clear=True), contextlib.redirect_stdout(output):
                result = m.main(["--event", str(path), "--event-name", "pull_request_target", "--concurrency-key"])
        self.assertEqual(result, 0)
        self.assertRegex(output.getvalue(), r"^lock_key=[a-f0-9]{64}\n$")

    def test_commands_and_document_put_use_native_payloads(self):
        class Transport:
            def __init__(self):
                self.calls = []
            def request(self, *args):
                self.calls.append(args)
                if args[0].endswith("format=json"):
                    return {"content": m.document()}
                return [{"success": True, "result": None}]
        transport = Transport()
        client = m.Fibery("never-output-this-secret", transport)
        client.link("fact-id", "evidence-id")
        payload = transport.calls[0][3][0]
        self.assertEqual(payload["args"]["entity"], {"fact-id": ["evidence-id"]})
        content = m.document("A fact")
        client.ensure_document("00000000-0000-0000-0000-000000000001", content)
        self.assertEqual(transport.calls[-1][2:], ("PUT", {"content": content}))

    def test_cli_never_echoes_event_text_or_credentials(self):
        event = pull_event()
        event["pull_request"]["title"] = "PRIVATE-TOKEN-EXAMPLE"
        event["repository"]["full_name"] = "PRIVATE-TOKEN-EXAMPLE/secret"
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            out, err = io.StringIO(), io.StringIO()
            with patch.dict("os.environ", {"FIBERY_API_TOKEN": "PRIVATE-TOKEN-EXAMPLE"}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                result = m.main(["--event", str(event_path), "--event-name", "pull_request_target"])
        self.assertEqual(result, 1)
        self.assertNotIn("PRIVATE-TOKEN-EXAMPLE", out.getvalue() + err.getvalue())
        self.assertIn("different repository", err.getvalue())


if __name__ == "__main__":
    unittest.main()
