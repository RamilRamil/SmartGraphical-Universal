# Phase 1 Data Model: Findings Overlay

Frontend-only types (TypeScript). No backend/persisted entities change.

## Existing inputs (unchanged)

- **Finding** (`frontend/src/api/types.ts`): `confidence`, `category`, `title`,
  `rule_id`, and `evidences: Evidence[]`.
- **Evidence**: `type_name`, `function_name`, `line_numbers` — the correlation key.
- **GraphNode**: `id`, `group` (`type|tile|function|state|...`), `type_name`,
  `label` — the match targets.

## New type: ConfidenceRank

Ordering helper: `high = 3`, `medium = 2`, `low = 1`, unknown = `0`.

## New type: NodeFindingSummary

Per graph node that owns at least one finding:

| Field | Meaning |
|-------|---------|
| `nodeId` | the `GraphNode.id` |
| `count` | number of findings attributed to this node |
| `maxConfidence` | `"high" \| "medium" \| "low"` — highest among the node's findings (drives color/intensity) |
| `findingRefs` | indices (or stable keys) into the findings list, for the side panel (US4) |

## New type: FindingsCorrelation (module output)

| Field | Meaning |
|-------|---------|
| `byNodeId` | `Map<string, NodeFindingSummary>` — for badging/coloring (US1) and the node panel (US4) |
| `nodeIdsForFinding(findingKey)` | resolved node id(s) for a given finding (US2 navigation) |
| `unmapped` | findings that matched no node (US2 #3, US5 honesty) |

## Matching rules (the correlation contract)

For each finding, take its primary evidence (`evidences[0]`, falling back across
evidences if the first lacks a type):

1. If `function_name` is present: match nodes where
   `group === "function" && type_name === ev.type_name && label === ev.function_name`.
2. Else if `type_name` is present: match nodes where
   `group ∈ {"type","tile"} && type_name === ev.type_name`.
3. Else: the finding is **unmapped**.

A finding may match more than one node (counted on each). A node with no matches
gets no summary entry (so US1 marks only owners; US3 filters to owners).

## Aggregation rules

- `count` = number of findings whose match set includes this node.
- `maxConfidence` = the highest `ConfidenceRank` among those findings, mapped back
  to its label.

## GraphView prop additions (additive — see contracts/graphview-props.md)

- `findingSummaries?: ReadonlyMap<string, NodeFindingSummary>` — drives node
  badge + confidence styling and the "only nodes with findings" filter.
- `focusNodeId?: string | null` — node to center + highlight on mount/update (US2).
- (US4 reuses GraphView's existing `selected` node + side panel, rendering its
  summary from `findingSummaries`.)

All additions are optional; omitting them yields today's behavior (no overlay).
