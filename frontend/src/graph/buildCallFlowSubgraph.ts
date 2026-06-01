import type { GraphData, GraphEdge, GraphNode } from "../api/types";

export type CallFlowDirection = "upstream" | "downstream" | "both";
export type CallFlowDepthMode = "limited" | "full";
export type CallFlowNodeRole = "function" | "stub";

export type CallFlowGraphNode = GraphNode & {
  callFlowRole: CallFlowNodeRole;
};

/** Non-function endpoints shown as leaf stubs in call flow (Phase 2). */
export const CALL_FLOW_STUB_GROUPS = new Set<GraphNode["group"]>([
  "external",
  "external_import",
  "type",
]);

export function isCallFlowStubGroup(group: GraphNode["group"]): boolean {
  return CALL_FLOW_STUB_GROUPS.has(group);
}

export const DEFAULT_CALL_FLOW_EDGE_KINDS = [
  "function_to_function",
  "cross_type_call",
  "cross_contract_call",
] as const;

export const CALL_FLOW_LIMITED_MAX_NODES = 80;
export const CALL_FLOW_FULL_MAX_NODES = 150;

export type CallFlowOptions = {
  rootFunctionId: string;
  direction: CallFlowDirection;
  depthMode: CallFlowDepthMode;
  /** 1..4 when depthMode is limited */
  depth: number;
  edgeKinds: ReadonlySet<string>;
  maxNodes: number;
};

export type CallFlowSubgraphResult = {
  nodes: CallFlowGraphNode[];
  edges: GraphEdge[];
  rootId: string;
  truncated: boolean;
  upstreamCount: number;
  downstreamCount: number;
  functionCount: number;
  stubCount: number;
};

export function callFlowDisplayLabel(
  node: GraphNode,
  opts?: { edgeLabel?: string },
): string {
  if (opts?.edgeLabel?.trim()) {
    return opts.edgeLabel.trim();
  }
  if (node.group !== "function") {
    const name = node.label || node.id;
    if (node.group === "external" || node.group === "external_import") {
      return `[ext] ${name}`;
    }
    if (node.group === "type") {
      return `[type] ${name}`;
    }
    return name;
  }
  const name = node.label || node.id;
  if (node.type_name) {
    return `${node.type_name}.${name}`;
  }
  return name;
}

function asCallFlowNode(node: GraphNode, role: CallFlowNodeRole): CallFlowGraphNode {
  return { ...node, callFlowRole: role };
}

function edgeLabelByStubTarget(edges: GraphEdge[]): Map<string, string> {
  const labels = new Map<string, string>();
  for (const edge of edges) {
    if (!edge.label?.trim()) continue;
    const existing = labels.get(edge.target);
    if (!existing) {
      labels.set(edge.target, edge.label.trim());
    }
  }
  return labels;
}

function clampDepth(depth: number): number {
  return Math.min(4, Math.max(1, Math.floor(depth)));
}

function bfsCollect(
  startId: string,
  adj: Map<string, string[]>,
  maxHops: number,
  maxNodes: number,
  nodeBudget: { count: number },
): { ids: Set<string>; truncated: boolean } {
  const ids = new Set<string>([startId]);
  let truncated = false;
  const queue: Array<{ id: string; hop: number }> = [{ id: startId, hop: 0 }];
  let qi = 0;

  while (qi < queue.length) {
    const { id, hop } = queue[qi]!;
    qi += 1;
    if (maxHops !== Infinity && hop >= maxHops) continue;
    for (const next of adj.get(id) ?? []) {
      if (ids.has(next)) continue;
      if (nodeBudget.count >= maxNodes) {
        truncated = true;
        return { ids, truncated };
      }
      ids.add(next);
      nodeBudget.count += 1;
      queue.push({ id: next, hop: hop + 1 });
    }
  }
  return { ids, truncated };
}

export function buildCallFlowSubgraph(
  data: GraphData,
  options: CallFlowOptions,
): CallFlowSubgraphResult {
  const rootId = options.rootFunctionId;
  const root = data.nodes.find((n) => n.id === rootId && n.group === "function");
  if (!root) {
    return {
      nodes: [],
      edges: [],
      rootId,
      truncated: false,
      upstreamCount: 0,
      downstreamCount: 0,
      functionCount: 0,
      stubCount: 0,
    };
  }

  const nodeById = new Map<string, GraphNode>();
  for (const node of data.nodes) {
    nodeById.set(node.id, node);
  }

  const functionById = new Map<string, GraphNode>();
  for (const node of data.nodes) {
    if (node.group === "function") {
      functionById.set(node.id, node);
    }
  }

  const isStubId = (id: string): boolean => {
    const node = nodeById.get(id);
    return node !== undefined && isCallFlowStubGroup(node.group);
  };

  const outAdj = new Map<string, string[]>();
  const inAdj = new Map<string, string[]>();
  for (const id of functionById.keys()) {
    outAdj.set(id, []);
    inAdj.set(id, []);
  }

  for (const edge of data.edges) {
    if (!options.edgeKinds.has(edge.kind)) continue;
    if (!functionById.has(edge.source) || !functionById.has(edge.target)) continue;
    outAdj.get(edge.source)!.push(edge.target);
    inAdj.get(edge.target)!.push(edge.source);
  }

  const maxHops =
    options.depthMode === "full" ? Infinity : clampDepth(options.depth);
  const nodeBudget = { count: 1 };
  let truncated = false;

  const upstreamIds = new Set<string>();
  const downstreamIds = new Set<string>();

  if (options.direction === "upstream" || options.direction === "both") {
    const up = bfsCollect(rootId, inAdj, maxHops, options.maxNodes, nodeBudget);
    for (const id of up.ids) upstreamIds.add(id);
    truncated = truncated || up.truncated;
  }

  if (options.direction === "downstream" || options.direction === "both") {
    const down = bfsCollect(rootId, outAdj, maxHops, options.maxNodes, nodeBudget);
    for (const id of down.ids) downstreamIds.add(id);
    truncated = truncated || down.truncated;
  }

  const allIds = new Set<string>([rootId]);
  for (const id of upstreamIds) allIds.add(id);
  for (const id of downstreamIds) allIds.add(id);

  const stubIds = new Set<string>();
  for (const edge of data.edges) {
    if (!options.edgeKinds.has(edge.kind)) continue;
    if (allIds.has(edge.source) && isStubId(edge.target)) {
      stubIds.add(edge.target);
    }
    if (allIds.has(edge.target) && isStubId(edge.source)) {
      stubIds.add(edge.source);
    }
  }

  const edgeIds = new Set<string>();
  const edges: GraphEdge[] = [];
  const visibleIds = new Set<string>([...allIds, ...stubIds]);
  for (const edge of data.edges) {
    if (!options.edgeKinds.has(edge.kind)) continue;
    if (!visibleIds.has(edge.source) || !visibleIds.has(edge.target)) continue;
    const srcFn = functionById.has(edge.source);
    const tgtFn = functionById.has(edge.target);
    const srcStub = isStubId(edge.source);
    const tgtStub = isStubId(edge.target);
    if (!srcFn && !tgtFn) continue;
    if (!srcFn && !srcStub) continue;
    if (!tgtFn && !tgtStub) continue;
    if (!allIds.has(edge.source) && !allIds.has(edge.target)) continue;
    if (edgeIds.has(edge.id)) continue;
    edgeIds.add(edge.id);
    edges.push(edge);
  }

  const stubLabels = edgeLabelByStubTarget(edges);
  const nodes: CallFlowGraphNode[] = [];
  for (const id of allIds) {
    const node = functionById.get(id);
    if (node) nodes.push(asCallFlowNode(node, "function"));
  }
  for (const id of stubIds) {
    const node = nodeById.get(id);
    if (node) nodes.push(asCallFlowNode(node, "stub"));
  }
  nodes.sort((a, b) => {
    const la = callFlowDisplayLabel(a, { edgeLabel: stubLabels.get(a.id) });
    const lb = callFlowDisplayLabel(b, { edgeLabel: stubLabels.get(b.id) });
    return la.localeCompare(lb);
  });

  const upstreamCount = [...upstreamIds].filter((id) => id !== rootId).length;
  const downstreamCount = [...downstreamIds].filter((id) => id !== rootId).length;
  const functionCount = allIds.size;
  const stubCount = stubIds.size;

  return {
    nodes,
    edges,
    rootId,
    truncated,
    upstreamCount,
    downstreamCount,
    functionCount,
    stubCount,
  };
}

export function defaultCallFlowOptions(rootFunctionId: string): CallFlowOptions {
  return {
    rootFunctionId,
    direction: "both",
    depthMode: "limited",
    depth: 2,
    edgeKinds: new Set(DEFAULT_CALL_FLOW_EDGE_KINDS),
    maxNodes: CALL_FLOW_LIMITED_MAX_NODES,
  };
}

export function expandAllCallFlowOptions(rootFunctionId: string): CallFlowOptions {
  return {
    rootFunctionId,
    direction: "both",
    depthMode: "full",
    depth: 2,
    edgeKinds: new Set(DEFAULT_CALL_FLOW_EDGE_KINDS),
    maxNodes: CALL_FLOW_FULL_MAX_NODES,
  };
}
