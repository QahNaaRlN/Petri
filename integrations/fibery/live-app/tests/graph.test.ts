import test from "node:test";
import assert from "node:assert/strict";
import {layoutGraph, NODE_HEIGHT, NODE_WIDTH, type GraphInput} from "../src/graph.ts";

const node = (id: string, predecessorIds: string[] = [], causeIds: string[] = []): GraphInput => ({
  id, key: id, predecessorIds, causeIds,
});

test("order edges do not imply causal edges; fork and join preserve their real edges", () => {
  const result = layoutGraph([node("A"), node("B", ["A"]), node("C", ["A"]), node("D", ["B", "C"])]);
  assert.equal(result.edges.length, 4);
  assert.ok(result.edges.every((edge) => edge.kind === "order"));
  assert.ok(result.positions.A.x < result.positions.B.x);
  assert.equal(result.positions.B.x, result.positions.C.x);
  assert.notEqual(result.positions.B.y, result.positions.C.y);
  assert.ok(result.positions.B.x < result.positions.D.x);
  assert.deepEqual(result.warnings, []);
});

test("a recorded order and a recorded cause remain two distinct relations", () => {
  const result = layoutGraph([node("A"), node("B", ["A", "A"], ["A", "A"])]);
  assert.deepEqual(result.edges, [
    {from: "A", to: "B", kind: "cause"},
    {from: "A", to: "B", kind: "order"},
  ]);
});

test("cycles retain edges, are warned about and do not invent a sequence inside the cycle", () => {
  const result = layoutGraph([node("A", ["B"]), node("B", ["A"]), node("C", ["B"])]);
  assert.equal(result.positions.A.x, result.positions.B.x);
  assert.ok(result.positions.C.x > result.positions.B.x);
  assert.equal(result.edges.length, 3);
  assert.equal(result.warnings.filter((warning) => warning.includes("Цикл")).length, 1);
});

test("self references are retained as a cycle rather than a fake predecessor", () => {
  const result = layoutGraph([node("A", ["A"])]);
  assert.deepEqual(result.edges, [{from: "A", to: "A", kind: "order"}]);
  assert.ok(result.warnings.some((warning) => warning.includes("Цикл")));
});

test("missing references are visible warnings and are never created as synthetic facts", () => {
  const result = layoutGraph([node("A", ["missing-order"], ["missing-cause"])]);
  assert.deepEqual(Object.keys(result.positions), ["A"]);
  assert.deepEqual(result.edges, []);
  assert.equal(result.warnings.length, 2);
});

test("a supplied fact from another spec participates without inferring any other relationship", () => {
  const boundary = node("other-spec-fact");
  const result = layoutGraph([node("current-spec-fact", [boundary.id]), boundary]);
  assert.deepEqual(result.edges, [{from: boundary.id, to: "current-spec-fact", kind: "order"}]);
  assert.ok(result.positions[boundary.id].x < result.positions["current-spec-fact"].x);
  assert.deepEqual(result.warnings, []);
});

test("input ordering does not alter layout or edges, and cards do not overlap", () => {
  const input = [node("A"), node("B", ["A"]), node("C"), node("D", [], ["C"])];
  const normal = layoutGraph(input);
  const reverse = layoutGraph([...input].reverse());
  assert.deepEqual(normal, reverse);
  const positions = Object.values(normal.positions);
  for (let i = 0; i < positions.length; i++) {
    for (let j = i + 1; j < positions.length; j++) {
      assert.ok(Math.abs(positions[i].x - positions[j].x) >= NODE_WIDTH || Math.abs(positions[i].y - positions[j].y) >= NODE_HEIGHT);
    }
  }
});

test("empty history and a long linked history are bounded and terminate", () => {
  const empty = layoutGraph([]);
  assert.equal(Object.keys(empty.positions).length, 0);
  assert.ok(empty.width >= NODE_WIDTH);
  const input = Array.from({length: 5000}, (_, i) => node(String(i).padStart(5, "0"), i ? [String(i - 1).padStart(5, "0")] : []));
  const result = layoutGraph(input);
  assert.equal(Object.keys(result.positions).length, 5000);
  assert.equal(result.edges.length, 4999);
  assert.deepEqual(result.warnings, []);
});
