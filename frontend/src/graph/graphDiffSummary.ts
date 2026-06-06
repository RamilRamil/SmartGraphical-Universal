import type {
  GraphDiffChangedNode,
  GraphDiffEdge,
  GraphDiffNode,
  GraphDiffResponse,
} from "../api/types";

/** Total number of structural changes across nodes and edges. */
export function graphDiffTotalChanges(diff: GraphDiffResponse): number {
  return (
    diff.added_node_count +
    diff.removed_node_count +
    diff.changed_node_count +
    diff.added_edge_count +
    diff.removed_edge_count
  );
}

/** True when the two graphs are structurally identical (no add/remove/change). */
export function isGraphDiffEmpty(diff: GraphDiffResponse): boolean {
  return graphDiffTotalChanges(diff) === 0;
}

/** Group nodes by their canonical `group` for display, keys sorted. */
export function groupNodesByGroup(
  nodes: GraphDiffNode[],
): { group: string; nodes: GraphDiffNode[] }[] {
  const byGroup = new Map<string, GraphDiffNode[]>();
  for (const node of nodes) {
    const key = node.group || "(none)";
    const bucket = byGroup.get(key);
    if (bucket) bucket.push(node);
    else byGroup.set(key, [node]);
  }
  return [...byGroup.keys()]
    .sort()
    .map((group) => ({ group, nodes: byGroup.get(group) as GraphDiffNode[] }));
}

/** Short human label for an edge, e.g. "a → b (kind)". */
export function describeEdge(edge: GraphDiffEdge): string {
  const base = `${edge.source} → ${edge.target}`;
  return edge.kind ? `${base} (${edge.kind})` : base;
}

/** Which signature fields changed between before/after of a changed node. */
export function changedFields(node: GraphDiffChangedNode): string[] {
  const fields: string[] = [];
  if (node.before.group !== node.after.group) fields.push("group");
  if (node.before.label !== node.after.label) fields.push("label");
  if (node.before.kind !== node.after.kind) fields.push("kind");
  return fields;
}
