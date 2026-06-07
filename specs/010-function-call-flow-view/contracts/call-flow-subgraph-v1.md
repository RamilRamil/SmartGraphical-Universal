# Contract: Call flow subgraph (client v1)

## Input

```typescript
type CallFlowDirection = "upstream" | "downstream" | "both";

type CallFlowDepthMode = "limited" | "full";

type CallFlowOptions = {
  rootFunctionId: string;
  direction: CallFlowDirection;
  depthMode: CallFlowDepthMode;
  /** Used when depthMode is limited; 1..4 per direction. Ignored when full. */
  depth: number;
  edgeKinds: ReadonlySet<string>;
  /** default 80 when limited, 150 when full */
  maxNodes?: number;
};

type CallFlowNodeRole = "function" | "stub";

type CallFlowGraphNode = GraphNode & { callFlowRole: CallFlowNodeRole };

type CallFlowSubgraph = {
  nodes: CallFlowGraphNode[]; // functions + optional stubs
  edges: GraphEdge[]; // subset of input kinds
  rootId: string;
  truncated: boolean;
  upstreamCount: number; // function hops only
  downstreamCount: number; // function hops only
  functionCount: number;
  stubCount: number;
};
```

## Edge inclusion rules

1. `edge.kind` must be in `edgeKinds`.
2. BFS traversal uses only edges where **both** endpoints are `group === "function"`.
3. After BFS, attach **stub** leaf nodes for included edges where one endpoint is a function in the subgraph and the other is `external`, `external_import`, or `type` (same id as main graph). Stubs do not expand BFS.
4. Traversal follows directed semantics: downstream uses `source -> target`; upstream uses reverse.

## Node labels

Display label: `{type_name}.{label}` when `type_name` present, else `label`.

## Empty cases

| Condition | `nodes` | UI message |
|-----------|---------|------------|
| Root not a function | `[]` | N/A (button hidden) |
| No incident call edges in direction | `[root]` | "No upstream/downstream calls in graph" |
| Cap exceeded | partial + `truncated: true` | "Showing first N functions; reduce depth or leave expand-all" |
| depthMode full | BFS until closure or cap | Same truncation banner |

## Stability

Same `GraphData` + options => identical node/edge id sets (deterministic BFS order).
