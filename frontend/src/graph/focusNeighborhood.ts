import type { GraphData, GraphNode } from "../api/types";

const FOCUS_ROOT_GROUPS = new Set<GraphNode["group"]>(["type", "tile"]);

/**
 * Two-hop undirected expansion from selected type/tile (variant B: shared hubs).
 * Returns null when focus is off or root is not a contract/tile node.
 */
export function buildFocusNodeSet(
  data: GraphData,
  selectedId: string | null,
  focusEnabled: boolean,
): Set<string> | null {
  if (!focusEnabled || !selectedId) return null;
  const root = data.nodes.find((n) => n.id === selectedId);
  if (!root || !FOCUS_ROOT_GROUPS.has(root.group)) return null;

  const idSet = new Set(data.nodes.map((n) => n.id));
  const adj = new Map<string, string[]>();
  for (const id of idSet) adj.set(id, []);
  for (const e of data.edges) {
    if (!idSet.has(e.source) || !idSet.has(e.target)) continue;
    adj.get(e.source)!.push(e.target);
    adj.get(e.target)!.push(e.source);
  }

  const result = new Set<string>([selectedId]);
  let layer = new Set<string>([selectedId]);
  for (let hop = 0; hop < 2; hop++) {
    const nextLayer = new Set<string>();
    for (const u of layer) {
      for (const v of adj.get(u) ?? []) {
        if (!result.has(v)) {
          result.add(v);
          nextLayer.add(v);
        }
      }
    }
    layer = nextLayer;
  }
  return result;
}

/**
 * Edges entirely inside the focus set that are not incident to the root (2nd-order in ego view).
 * Branches from the selected contract stay at full emphasis.
 */
export function buildFocusSecondaryEdgeIds(
  data: GraphData,
  rootId: string,
  focusNodeIds: Set<string>,
): Set<string> {
  const secondary = new Set<string>();
  for (const e of data.edges) {
    if (!focusNodeIds.has(e.source) || !focusNodeIds.has(e.target)) continue;
    if (e.source !== rootId && e.target !== rootId) secondary.add(e.id);
  }
  return secondary;
}
