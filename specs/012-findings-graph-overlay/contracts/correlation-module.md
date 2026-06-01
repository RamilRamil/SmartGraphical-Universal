# Contract: correlateFindings (pure frontend module)

**Location**: `frontend/src/graph/correlateFindings.ts` (new), tested by
`correlateFindings.test.ts`.

## Signature

```ts
import type { Finding, GraphNode } from "../api/types";

export type Confidence = "high" | "medium" | "low";

export type NodeFindingSummary = {
  nodeId: string;
  count: number;
  maxConfidence: Confidence;
  findingRefs: number[]; // indices into the findings array passed in
};

export type FindingsCorrelation = {
  byNodeId: ReadonlyMap<string, NodeFindingSummary>;
  /** node id(s) a finding maps to; [] means unmapped. */
  nodeIdsForFindingIndex: (index: number) => string[];
  /** indices of findings that mapped to no node. */
  unmappedIndices: number[];
};

export function correlateFindings(
  findings: readonly Finding[],
  nodes: readonly GraphNode[],
): FindingsCorrelation;
```

## Rules

- **R1 (function match)**: a finding with evidence `type_name` + `function_name`
  maps to every node with `group === "function" && type_name === ev.type_name &&
  label === ev.function_name`.
- **R2 (container match)**: a finding with evidence `type_name` and no
  `function_name` maps to every node with `group ∈ {"type","tile"} && type_name
  === ev.type_name`.
- **R3 (unmapped)**: a finding with no resolvable evidence target appears in
  `unmappedIndices` and contributes to no node summary.
- **R4 (no id reconstruction)**: matching MUST use `type_name`/`label`, never a
  reconstructed `type:`/`function:`/`tile:` id string (language-agnostic).
- **R5 (aggregation)**: `count` = findings mapped to the node; `maxConfidence` =
  highest of `high>medium>low` (unknown treated as lowest) among them.
- **R6 (multi-match)**: a finding mapping to N nodes counts on all N.
- **R7 (purity)**: no DOM, no cytoscape, no network — input arrays in, plain data
  out (so it is unit-testable in isolation).

## Test matrix (Vitest)

| Case | Asserts |
|------|---------|
| Solidity function finding | maps to the `function` node with matching type_name+label |
| C (`tile:` container) finding | type-only evidence maps to the `tile` group node |
| Rust function finding | same matching works with rust-shaped nodes |
| mixed confidence on one node | `count` correct, `maxConfidence` = highest |
| multi-match | finding counted on each matching node |
| unmapped | finding with empty/unknown evidence is in `unmappedIndices`, no node summary |
