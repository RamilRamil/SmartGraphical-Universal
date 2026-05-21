import type { GraphData, GraphEdge, GraphNode } from "../api/types";

/** Bundle / inheritance links (inter-contract view only). */
export const INTER_CONTRACT_EDGE_KINDS = new Set<string>([
  "cross_type_call",
  "cross_type_state",
  "cross_type_state_read",
  "cross_type_state_write",
]);

/** External calls optional on the full graph. */
export const FULL_GRAPH_EXTERNAL_EDGE_KINDS = new Set<string>([
  "cross_contract_call",
  "function_to_object",
]);

/** File-level bundle links (often redundant with cross-type semantics). */
const BUNDLE_FILE_LINK_KINDS = new Set<string>([
  "bundle_import",
  "tile_to_tile",
]);

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

/** Edge ids for bundle file links suppressed when a cross-type edge links the same pair. */
export function edgeIdsDroppedAsRedundantBundleLinks(
  edges: GraphEdge[],
): Set<string> {
  const kept = dropRedundantBundleFileLinks(edges);
  const keptIds = new Set(kept.map((e) => e.id));
  const dropped = new Set<string>();
  for (const e of edges) {
    if (BUNDLE_FILE_LINK_KINDS.has(e.kind) && !keptIds.has(e.id)) {
      dropped.add(e.id);
    }
  }
  return dropped;
}

/** Contract-box link (extends / type-to-type); inter-contract view only on full graph. */
export function isTypeCompoundInterContractEdge(
  edge: GraphEdge,
  nodeById: Map<string, GraphNode>,
): boolean {
  if (!INTER_CONTRACT_EDGE_KINDS.has(edge.kind)) {
    return false;
  }
  const src = nodeById.get(edge.source);
  const tgt = nodeById.get(edge.target);
  if (src?.group === "type" && tgt?.group === "type") {
    return true;
  }
  const label = String(edge.label ?? "");
  return label.startsWith("extends ");
}

function dropRedundantBundleFileLinks(edges: GraphEdge[]): GraphEdge[] {
  const semanticPairs = new Set<string>();
  for (const e of edges) {
    if (INTER_CONTRACT_EDGE_KINDS.has(e.kind)) {
      semanticPairs.add(`${e.source}|${e.target}`);
    }
  }
  if (semanticPairs.size === 0) {
    return edges;
  }
  return edges.filter(
    (e) =>
      !BUNDLE_FILE_LINK_KINDS.has(e.kind) ||
      !semanticPairs.has(`${e.source}|${e.target}`),
  );
}

/**
 * Full-graph view: always drop type-compound links; optional function-level / external.
 */
export function filterFullGraphEdges(
  graph: GraphData,
  showCrossContractCalls: boolean,
): GraphData {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  let edges = graph.edges.filter(
    (e) => !isTypeCompoundInterContractEdge(e, nodeById),
  );
  if (!showCrossContractCalls) {
    edges = edges.filter((e) => {
      if (INTER_CONTRACT_EDGE_KINDS.has(e.kind)) {
        return false;
      }
      if (FULL_GRAPH_EXTERNAL_EDGE_KINDS.has(e.kind)) {
        return false;
      }
      return true;
    });
  }
  if (edges.length === graph.edges.length) {
    return graph;
  }
  const hints = graph.exploration_hints;
  return {
    ...graph,
    edges,
    exploration_hints: hints
      ? {
          ...hints,
          edge_count: edges.length,
          call_edge_count: edges.filter((e) =>
            e.kind.includes("call"),
          ).length,
        }
      : undefined,
  };
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

  const overviewEdges = dropRedundantBundleFileLinks(edges);

  const hints = graph.exploration_hints;
  return {
    ...graph,
    nodes,
    edges: overviewEdges,
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
