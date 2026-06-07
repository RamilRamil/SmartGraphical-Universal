# Research: Function Call Flow View

## Existing UI

| Feature | Behavior | Gap |
|---------|----------|-----|
| Side panel (`GraphView.tsx`) | Metadata, import usage, code | No topology |
| Focus selection | Contract/tile only; undirected 2-hop | Wrong root and direction |
| Inter-contract overview | Contract-level graph | Not function-centric |
| Cross-contract toggle | Hides/shows edge kinds on main canvas | Not a dedicated view |

## Edge semantics (must follow)

From `docs/graph_schema_logic.md` and spec 007:

- `function_to_function`: caller -> callee (same contract).
- `cross_type_call`: child caller -> parent callee.
- `cross_contract_call`: caller function -> external/target type.

Subgraph builder walks **outgoing** for downstream and **incoming** for upstream using only these kinds.

## Algorithm sketch

```text
Input: GraphData, rootFunctionId, direction, depthMode, depth, edgeKinds, maxNodes
1. Index function nodes by id.
2. Build adjacency:
   - out[u] = [{ v, edge }] for call kinds where source=u
   - in[u]  = [{ v, edge }] where target=u
3. If depthMode=limited: BFS upstream/downstream with hop limit depth
   If depthMode=full: BFS until queue empty (both directions when direction=both)
4. Union nodes/edges; stop early if |nodes| >= maxNodes (truncated=true)
5. Return { nodes, edges, truncated, stats }
```

**Expand full chain (UI):** sets depthMode=full, direction=both, maxNodes=150.

Resolve endpoints: only edges where both endpoints are `group === "function"`. If edge targets a non-function (object/external), v1 either skips or shows a synthetic external node (P2).

## Cytoscape in modal

Reuse patterns from `GraphView.tsx`:
- Register fcose/cose-bilkent only if needed; prefer **dagre** for DAG-like call flow.
- Smaller stylesheet: function nodes only, edge arrows by kind color from main graph palette.
- No compound nesting in v1 (flat nodes with label `Contract.fn`).

## Risks

| Risk | Mitigation |
|------|------------|
| Cycles in call graph | BFS with visited set; optional cycle badge on back-edge |
| Huge fan-out | Depth limit + node cap + truncation message |
| Missing calls in payload | Empty state + link to schema doc hint |
| cross_type_call parent on other file | Include if node id present in same GraphData |

## Alternatives considered

1. **Filter main canvas in-place** — simpler but loses compound context and fights layout; rejected for v1.
2. **Server-side subgraph API** — accurate but needs new endpoint and cache; defer.
3. **Mermaid export only** — weak for exploration; supplement in P3.
