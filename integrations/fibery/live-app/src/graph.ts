export type GraphInput = {
  id: string;
  key: string;
  predecessorIds: string[];
  causeIds: string[];
};

export type GraphEdge = {from: string; to: string; kind: "order" | "cause"};
export type GraphLayout = {
  positions: Record<string, {x: number; y: number}>;
  edges: GraphEdge[];
  width: number;
  height: number;
  warnings: string[];
};

export const NODE_WIDTH = 300;
export const NODE_HEIGHT = 160;

const PADDING = 40;
const COLUMN_GAP = 100;
const ROW_GAP = 64;
const compareText = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Positions only recorded edges. A causal edge is never inferred from an order
 * edge. Strongly connected components share a column, so a contradictory cycle
 * cannot be presented as a fabricated topological sequence.
 */
export function layoutGraph(input: GraphInput[]): GraphLayout {
  const warnings: string[] = [];
  const nodes = new Map<string, GraphInput>();
  for (const node of [...input].sort((a, b) => compareText(a.key, b.key) || compareText(a.id, b.id))) {
    if (nodes.has(node.id)) {
      warnings.push(`Повторный идентификатор узла ${node.id}; показана одна запись.`);
      continue;
    }
    nodes.set(node.id, node);
  }
  const compareIds = (a: string, b: string) =>
    compareText(nodes.get(a)?.key ?? a, nodes.get(b)?.key ?? b) || compareText(a, b);
  const ids = [...nodes.keys()].sort(compareIds);
  const edges: GraphEdge[] = [];
  const edgeKeys = new Set<string>();
  const adjacency = new Map(ids.map((id) => [id, new Set<string>()]));
  const reversed = new Map(ids.map((id) => [id, new Set<string>()]));
  for (const id of ids) {
    const node = nodes.get(id)!;
    for (const [kind, references] of [
      ["order", node.predecessorIds],
      ["cause", node.causeIds],
    ] as const) {
      for (const from of [...new Set(references)].sort(compareIds)) {
        if (!nodes.has(from)) {
          warnings.push(
            `${node.key}: ${kind === "order" ? "предыдущий узел" : "причина"} ${from} отсутствует в загруженном графе.`,
          );
          continue;
        }
        const edgeKey = JSON.stringify([from, id, kind]);
        if (edgeKeys.has(edgeKey)) continue;
        edgeKeys.add(edgeKey);
        edges.push({from, to: id, kind});
        adjacency.get(from)!.add(id);
        reversed.get(id)!.add(from);
      }
    }
  }
  edges.sort((a, b) => compareIds(a.from, b.from) || compareIds(a.to, b.to) || compareText(a.kind, b.kind));

  // Iterative Kosaraju avoids recursion depth limits on long event histories.
  const visited = new Set<string>();
  const finish: string[] = [];
  for (const start of ids) {
    if (visited.has(start)) continue;
    const stack: {id: string; expanded: boolean}[] = [{id: start, expanded: false}];
    while (stack.length) {
      const item = stack.pop()!;
      if (item.expanded) {
        finish.push(item.id);
        continue;
      }
      if (visited.has(item.id)) continue;
      visited.add(item.id);
      stack.push({id: item.id, expanded: true});
      const children = [...adjacency.get(item.id)!].sort(compareIds).reverse();
      for (const child of children) if (!visited.has(child)) stack.push({id: child, expanded: false});
    }
  }

  const componentById = new Map<string, number>();
  const components: string[][] = [];
  for (const start of [...finish].reverse()) {
    if (componentById.has(start)) continue;
    const index = components.length;
    const members: string[] = [];
    const stack = [start];
    componentById.set(start, index);
    while (stack.length) {
      const id = stack.pop()!;
      members.push(id);
      for (const parent of [...reversed.get(id)!].sort(compareIds).reverse()) {
        if (componentById.has(parent)) continue;
        componentById.set(parent, index);
        stack.push(parent);
      }
    }
    members.sort(compareIds);
    components.push(members);
    if (members.length > 1 || adjacency.get(members[0])!.has(members[0])) {
      warnings.push(`Цикл связей: ${members.map((id) => nodes.get(id)!.key).join(", ")}. Узлы показаны на одном уровне.`);
    }
  }

  const outgoing = components.map(() => new Set<number>());
  const indegrees = components.map(() => 0);
  const ranks = components.map(() => 0);
  for (const edge of edges) {
    const from = componentById.get(edge.from)!;
    const to = componentById.get(edge.to)!;
    if (from === to || outgoing[from].has(to)) continue;
    outgoing[from].add(to);
    indegrees[to] += 1;
  }
  const compareComponents = (a: number, b: number) => compareIds(components[a][0], components[b][0]);
  const ready = indegrees.flatMap((degree, i) => (degree === 0 ? [i] : [])).sort(compareComponents);
  while (ready.length) {
    const from = ready.shift()!;
    for (const to of [...outgoing[from]].sort(compareComponents)) {
      ranks[to] = Math.max(ranks[to], ranks[from] + 1);
      indegrees[to] -= 1;
      if (indegrees[to] === 0) {
        ready.push(to);
        ready.sort(compareComponents);
      }
    }
  }

  const columns = new Map<number, string[]>();
  for (const [index, component] of components.entries()) {
    const rank = ranks[index];
    columns.set(rank, [...(columns.get(rank) ?? []), ...component]);
  }
  const positions: Record<string, {x: number; y: number}> = Object.create(null);
  for (const [rank, members] of columns) {
    members.sort(compareIds);
    members.forEach((id, row) => {
      positions[id] = {
        x: PADDING + rank * (NODE_WIDTH + COLUMN_GAP),
        y: PADDING + row * (NODE_HEIGHT + ROW_GAP),
      };
    });
  }
  const maxRank = Math.max(0, ...columns.keys());
  const maxRows = Math.max(1, ...[...columns.values()].map((column) => column.length));
  return {
    positions,
    edges,
    width: PADDING * 2 + (maxRank + 1) * NODE_WIDTH + maxRank * COLUMN_GAP,
    height: PADDING * 2 + maxRows * NODE_HEIGHT + (maxRows - 1) * ROW_GAP,
    warnings: [...new Set(warnings)],
  };
}
