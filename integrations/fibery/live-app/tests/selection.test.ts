import test from "node:test";
import assert from "node:assert/strict";
import {selectFactScope} from "../src/selection.ts";
import type {Fact} from "../src/model.ts";

const fact = (id: string, specId: string | null, planId: string | null, predecessors: string[] = [], causes: string[] = []): Fact => ({
  id, publicId: id, key: id, name: id, type: "Petri Human View/WorkNode",
  specId, planId, kind: "observation", state: "recorded",
  predecessorIds: predecessors, causeIds: causes, evidenceIds: [],
  documentSecret: null, occurredAt: null,
});

test("all versions includes old and new facts without assigning an unassigned fact", () => {
  const all = [fact("old", "S1", "P1"), fact("new", "S1", "P2"), fact("unknown-plan", "S1", null), fact("unassigned", null, "P1")];
  const result = selectFactScope(all, "S1", "P2", false);
  assert.deepEqual(result.primary.map((node) => node.id), ["old", "new", "unknown-plan"]);
  assert.deepEqual(result.graphFacts.map((node) => node.id), ["old", "new", "unknown-plan"]);
  assert.equal(all[3].specId, null);
});

test("switching version filters preserves original plan identifiers and input arrays", () => {
  const all = [fact("old", "S1", "P1"), fact("new", "S1", "P2")];
  const snapshot = JSON.stringify(all);
  for (const item of all) {
    Object.freeze(item.predecessorIds);
    Object.freeze(item.causeIds);
    Object.freeze(item);
  }
  Object.freeze(all);
  assert.deepEqual(selectFactScope(all, "S1", "P1", true).primary.map((node) => node.id), ["old"]);
  assert.deepEqual(selectFactScope(all, "S1", "P2", true).primary.map((node) => node.id), ["new"]);
  assert.deepEqual(selectFactScope(all, "S1", "P1", false).primary.map((node) => node.id), ["old", "new"]);
  assert.equal(JSON.stringify(all), snapshot);
  assert.equal(all[0].planId, "P1");
  assert.equal(all[1].planId, "P2");
});

test("old-plan and cross-spec references remain context without joining the selected primary scope", () => {
  const old = fact("old", "S1", "P1");
  const external = fact("external", "S2", "Q1");
  const selected = fact("selected", "S1", "P2", [old.id], [external.id]);
  const result = selectFactScope([old, external, selected], "S1", "P2", true);
  assert.deepEqual(result.primary.map((node) => node.id), ["selected"]);
  assert.deepEqual(result.graphFacts.map((node) => node.id), ["selected", "old", "external"]);
  assert.equal(result.graphFacts[1].planId, "P1");
  assert.equal(result.graphFacts[2].specId, "S2");
});

test("context includes explicit outgoing targets but stops after one hop", () => {
  const selected = fact("selected", "S1", "P1");
  const target = fact("target", "S2", "Q1", [selected.id]);
  const secondHop = fact("second-hop", "S3", "R1", [target.id]);
  const unrelated = fact("unrelated", "S2", "Q1");
  const result = selectFactScope([selected, target, secondHop, unrelated], "S1", "P1", true);
  assert.deepEqual(result.graphFacts.map((node) => node.id), ["selected", "target"]);
});

test("unassigned facts can be explicit boundary context but never primary or silently assigned", () => {
  const prior = fact("prior-unassigned", null, null);
  const selected = fact("selected", "S1", "P1", [prior.id]);
  const target = fact("target-unassigned", null, null, [], [selected.id]);
  const unrelated = fact("unrelated-unassigned", null, null);
  const all = [prior, selected, target, unrelated];
  const result = selectFactScope(all, "S1", "P1", true);
  assert.deepEqual(result.primary.map((node) => node.id), ["selected"]);
  assert.deepEqual(result.graphFacts.map((node) => node.id), ["selected", "prior-unassigned", "target-unassigned"]);
  assert.equal(prior.specId, null);
  assert.equal(target.specId, null);
});

test("no selected plan cannot treat unknown historical versions as that selected plan", () => {
  const all = [fact("unknown-plan", "S1", null)];
  assert.deepEqual(selectFactScope(all, "S1", null, true), {primary: [], graphFacts: []});
  assert.equal(selectFactScope(all, "S1", null, false).primary.length, 1);
});

test("empty primary scope does not leak disconnected records into a graph", () => {
  const result = selectFactScope([fact("other", "S2", "P1", ["missing"])], "S1", "P1", false);
  assert.deepEqual(result, {primary: [], graphFacts: []});
});
