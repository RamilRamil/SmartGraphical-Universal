# Phase 0 Research: Findings Overlay

## D1. Where does correlation live — backend serializer or frontend?

**Decision**: Frontend, as a pure module (`frontend/src/graph/correlateFindings.ts`).

**Rationale**: `ScanDetailPage` already fetches both `findings[]` (via `useScan`)
and the graph payload (via `useGraph`) in the same component, so both datasets
are present at render time with no extra request. Doing correlation in the
frontend means **zero backend payload change** — the strongest form of
constitution Principle VI (stable contracts). It also matches the existing
testable pure-module pattern (`focusNeighborhood.ts`, `intraCompoundLayout.ts`,
`buildCallFlowSubgraph.ts`, each with a `.test.ts`).

**Alternatives considered**:
- Backend serializer enrichment (attach `findings_summary` to each node): would
  require joining stored `findings.json` with `graph.json` at scan or fetch time,
  changing the graph payload and adding migration concerns for old scans.
  Rejected for v1 — more surface area, breaks the "additive or nothing" goal.
  Left as a documented future option if a non-UI consumer ever needs it.

## D2. Correlation key — do we reconstruct node ids?

**Decision**: No id reconstruction. Match on semantic fields already present on
both sides:
- Function finding: `evidence.type_name === node.type_name && evidence.function_name === node.label && node.group === "function"`.
- Type/container finding (no function): `evidence.type_name === node.type_name && node.group ∈ {"type","tile"}`.
- (State entities: findings evidence does not carry a distinct state-entity field
  today, so state-node correlation is best-effort and not required for v1.)

**Rationale**: `GraphNode` carries `type_name` and `label` (verified in
`frontend/src/api/types.ts`), and finding evidence carries `type_name` +
`function_name`. Matching these avoids duplicating the serializer's id scheme
(`type:`/`function:`/`tile:`), which differs by language and would be fragile to
mirror. This makes correlation inherently language-agnostic (Principle IV).

**Alternatives considered**: reconstruct `function:<path>.<label>` ids in the
frontend — rejected (couples the frontend to backend id formatting; the C `tile:`
vs Solidity `type:` split, see KNOWN_QUIRKS Quirk 6, makes this brittle).

## D3. Confidence ordering and honest styling

**Decision**: Rank `high > medium > low`; any unknown value ranks lowest. A
node's overlay color/intensity is derived from the **highest** confidence among
its findings; a count badge shows the total. Low-only nodes use a visibly muted
style; high uses the most prominent.

**Rationale**: Principle II — the tool must not present a heuristic match as
certainty. Encoding "max confidence" with an honest intensity ramp communicates
"look here, and here's how strongly" without alarmism.

## D4. A finding that maps to multiple nodes

**Decision**: Attribute the finding to every matched node (so each node's count
includes it). For finding→graph navigation (US2), focus the first/best match and
indicate when there are multiple.

**Rationale**: Ambiguous names are rare but real; counting on all matches is
truthful, and focusing one keeps navigation deterministic.

## D5. Unmapped findings

**Decision**: A finding whose evidence resolves to no node is collected in an
`unmapped` list returned by the module. The finding→graph affordance for such a
finding is shown but, when activated, explains "not locatable on the graph"
(FR-005). Nothing is silently dropped.

**Rationale**: Principle II/V — surfacing the gap is more honest than hiding it,
and it signals where evidence inference (a future feature) could improve.

## D6. Navigation and filtering mechanics

**Decision**: Reuse existing patterns. US2 navigation = `ScanDetailPage` sets the
results tab to `graph` and passes a `focusNodeId` prop into `GraphView`, which
centers and highlights it (GraphView already owns a cytoscape `Core` and a
`selected` node + side panel). US3 "only nodes with findings (+neighbors)" is a
GraphView toggle that hides nodes absent from the correlation set, analogous to
the existing focus/filter toggles. US4 reuses GraphView's existing side panel to
list the selected node's findings.

**Rationale**: minimal new surface; consistent UX with the current graph
controls; keeps logic testable in the pure module while components stay thin.

## D7. Testing approach

**Decision**: Vitest unit tests for `correlateFindings` covering: a Solidity-
shaped case (`type:`/`function:` nodes), a C-shaped case (`tile:`/`function:`),
a Rust-shaped case, mixed-confidence aggregation (max + count), multi-match, and
unmapped. No backend test needed (no backend change).

**Rationale**: Principle VII — the correlation is the only new logic and is fully
covered by pure-module tests; component wiring is thin and exercised manually via
quickstart.
