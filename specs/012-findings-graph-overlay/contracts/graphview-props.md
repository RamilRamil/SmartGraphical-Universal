# Contract: GraphView additive props

**Location**: `frontend/src/components/GraphView.tsx`.

The current contract is `GraphView({ graph }: { graph: GraphData })`. This feature
adds **optional** props; omitting them preserves today's behavior exactly.

## Added props

```ts
type GraphViewProps = {
  graph: GraphData;
  // --- added by feature 012 (all optional) ---
  findingSummaries?: ReadonlyMap<string, NodeFindingSummary>;
  focusNodeId?: string | null;
};
```

## Behavior

- **B1 (overlay, US1)**: when `findingSummaries` is provided, each node whose id
  is a key gets a finding-count badge and a border/halo styled by its
  `maxConfidence` (high = most prominent, low = muted). Nodes absent from the map
  are styled as today.
- **B2 (focus, US2)**: when `focusNodeId` changes to a non-null id present in the
  graph, GraphView centers and highlights that node (reusing its cytoscape
  `Core`/selection). A `focusNodeId` not present in the graph is a no-op (the
  caller is responsible for the "unmapped" message).
- **B3 (filter, US3)**: GraphView exposes an internal toggle "Only nodes with
  findings" (enabled only when `findingSummaries` is non-empty) that hides nodes
  absent from the map; a second toggle additionally keeps their direct neighbors;
  an explicit empty state shows when nothing qualifies.
- **B4 (node panel, US4)**: when a node with a summary is selected, GraphView's
  existing side panel additionally lists that node's findings (title, category,
  confidence); a node with no summary states it has none.
- **B5 (back-compat)**: with neither new prop set, GraphView renders identically
  to the pre-012 version (no overlay, no new toggles beyond a disabled state).

## Caller (ScanDetailPage) contract

- Computes `correlateFindings(findings, graphData.nodes)` once (memoized) when
  both are available.
- Passes `findingSummaries = correlation.byNodeId` to GraphView.
- For finding→graph navigation: on a finding's "Show on graph", resolve
  `correlation.nodeIdsForFindingIndex(i)`; if non-empty, `setTab("graph")` and set
  `focusNodeId` to the first id; if empty, show "not locatable on the graph".
