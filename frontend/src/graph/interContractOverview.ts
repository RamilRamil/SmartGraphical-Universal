import type { GraphData, GraphEdge, GraphNode } from "../api/types";

const COMPOUND_GROUPS = new Set<string>(["type", "tile"]);
/** Top-level nodes kept in overview (compound roots + loose externals). */
const EXPOSED_TOP_GROUPS = new Set<string>([
  "type",
  "tile",
  "external",
  "external_import",
]);

function rootCompoundId(
  nodeId: string,
  byId: Map<string, GraphNode>,
): string | null {
  const seen = new Set<string>();
  let cur: string | undefined = nodeId;
  while (cur !== undefined && cur !== "" && !seen.has(cur)) {
    seen.add(cur);
    const n = byId.get(cur);
    if (!n) return null;
    if (COMPOUND_GROUPS.has(n.group)) return n.id;
    cur = n.parent;
  }
  return null;
}

function mapEndpoint(
  id: string,
  byId: Map<string, GraphNode>,
): string | null {
  const n = byId.get(id);
  if (!n) return null;
  if (n.group === "external" || n.group === "external_import") return id;
  if (COMPOUND_GROUPS.has(n.group)) return id;
  return rootCompoundId(id, byId);
}

/**
 * Collapse each contract/tile compound to a single node and keep only edges
 * whose endpoints lie in different compounds (or reach externals).
 */
export function toInterContractOverviewGraph(graph: GraphData): GraphData {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const raw = graph.nodes.filter((n) => EXPOSED_TOP_GROUPS.has(n.group));
  const nodeIds = new Set(raw.map((n) => n.id));
  const sanitized = raw.map((n) => ({
    ...n,
    parent: n.parent && nodeIds.has(n.parent) ? n.parent : undefined,
  }));
  /** Solidity / modular graphs: drop file tiles and flatten so layout can spread contracts. */
  const hasContractTypes = sanitized.some((n) => n.group === "type");
  const nodes = hasContractTypes
    ? sanitized
        .filter((n) => n.group !== "tile")
        .map((n) => ({ ...n, parent: undefined }))
    : sanitized;
  const keptIds = new Set(nodes.map((n) => n.id));

  const seenEdge = new Set<string>();
  const edges: GraphEdge[] = [];
  let ovIndex = 0;

  for (const e of graph.edges) {
    const a = mapEndpoint(e.source, byId);
    const b = mapEndpoint(e.target, byId);
    if (!a || !b) continue;
    if (a === b) continue;
    if (!keptIds.has(a) || !keptIds.has(b)) continue;
    const key = `${a}|${b}|${e.kind}`;
    if (seenEdge.has(key)) continue;
    seenEdge.add(key);
    ovIndex += 1;
    edges.push({
      ...e,
      id: `ov:${ovIndex}:${a}:${b}:${e.kind}`,
      source: a,
      target: b,
    });
  }

  const hints = graph.exploration_hints;
  return {
    ...graph,
    nodes,
    edges,
    exploration_hints: hints
      ? {
          ...hints,
          node_count: nodes.length,
          edge_count: edges.length,
        }
      : {
          call_edges_are_heuristic: false,
          call_edge_count: edges.length,
          node_count: nodes.length,
          edge_count: edges.length,
        },
  };
}
