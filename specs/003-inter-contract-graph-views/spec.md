# Feature Specification: Inter-Contract Graph Views

**Feature Branch**: `003-inter-contract-graph-views`

**Created**: 2026-05-21

**Status**: Implemented

**Input**: Separate full-graph vs inter-contract edge visibility; remove duplicate `cross_type_call` + `bundle_import` arrows in inter-contract overview when inheritance/import imply the same link.

## User Scenarios

### US1 - Full graph without bundle noise (P1)

**Given** a Solidity bundle (e.g. `tests/fixtures/solidity/cross_type/`) is loaded on the **full** graph, **When** the user explores contracts and functions, **Then** `cross_type_call` / `cross_type_state*` / `extends` edges between contract compounds are **not** rendered and **not** selectable; internal `function_to_function` and state read/write edges within a contract remain visible.

**Why this priority**: Full graph already shows call structure inside each contract; bundle-level `extends` and cross-type links duplicate inter-contract semantics.

**Independent Test**: Open cross_type fixture bundle, full graph, confirm no red `extends OraclePeer` edge between `ValidatorChild` and `OraclePeer` type nodes; panel cannot show that edge after click.

---

### US2 - Cross-contract toggle on full graph (P1)

**Given** full graph view (keeper), **When** user views the graph with toggle on or off, **Then** **contract-compound** links (`cross_type_*` with both endpoints `group: type`, or label `extends …`) are **never** shown (e.g. no `ValidatorChild` -> `RewardBase` `extends RewardBase`).

**Given** toggle is **on**, **When** user explores the full graph, **Then** **function-level** `cross_type_call` (e.g. `approveValidators` -> `_collateralize`) and `cross_contract_call` / `function_to_object` become visible via visibility-only update (no Cytoscape rebuild).

**Given** toggle is **off**, **When** user explores the full graph, **Then** all `cross_type_*` and external call edges are hidden except those never shown per US1 (type-compound links always hidden).

**Given** **Inter-contract** view, **When** user looks at toolbar, **Then** the cross-contract toggle is disabled (contract-level links always shown there).

---

### US3 - Inter-contract shows semantic links only (P1)

**Given** inter-contract overview for cross_type fixture bundle, **When** `ValidatorChild` extends and imports `OraclePeer`, **Then** exactly one directed link between those contract nodes is shown for semantics (`cross_type_call` / `extends OraclePeer`), and **no** parallel `bundle_import` / `solidity_import` edge for the same pair.

**Why this priority**: File import is implied by inheritance; two arrows between the same contracts confuse the overview.

**Independent Test**: Inter-contract mode; edge list between Validators and Oracles has `cross_type_call` only, not `bundle_import`.

---

### US4 - Import-only bundle pairs keep file link (P2)

**Given** contract A imports contract B's file but does **not** inherit or cross-call B, **When** inter-contract overview is shown, **Then** `bundle_import` (or C `tile_to_tile`) between A and B remains visible.

**Independent Test**: Vitest `keeps bundle_import when no semantic cross-type edge exists`.

## Edge Cases

- Multiple `cross_type_*` edges between the same pair still suppress one `bundle_import` for that pair.
- Reverse direction: dedupe key is directed `source|target`; import and `extends` share child -> parent direction in keeper fixture.
- Full graph still contains `bundle_import` in API payload; filtering is view-layer only (no backend graph mutation).
- C bundles: `tile_to_tile` deduped like `bundle_import` when semantic cross-type edge exists between tiles.

## Requirements

### Functional Requirements

- **FR-001**: Full graph MUST **always** hide **type-compound** inter-contract edges (`source` and `target` are `group: type`, or label prefix `extends `).
- **FR-002**: Full graph MUST show **function-level** `INTER_CONTRACT_EDGE_KINDS` and `FULL_GRAPH_EXTERNAL_EDGE_KINDS` only when **Show cross-contract calls** is on (default off); MUST NOT rebuild Cytoscape on toggle.
- **FR-003**: Inter-contract overview MUST keep semantic cross-type edges between different contract compounds.
- **FR-004**: Inter-contract overview MUST drop `bundle_import` and `tile_to_tile` for pair `(A,B)` when any `cross_type_*` edge already maps to `(A,B)` after compound collapse.
- **FR-005**: `applyGraphVisibility` MUST mirror FR-001/FR-002 as defense in depth; edge tap and node highlight MUST ignore non-visible edges.
- **FR-006**: Selecting a hidden inter-contract edge in panel MUST clear when switching from inter-contract to full graph.

### Key Entities

- **INTER_CONTRACT_EDGE_KINDS**: bundle semantics shown only in inter-contract view.
- **FULL_GRAPH_EXTERNAL_EDGE_KINDS**: optional external call edges on full graph.
- **BUNDLE_FILE_LINK_KINDS**: `bundle_import`, `tile_to_tile` — file/TU linkage, subordinate to cross-type semantics in overview.

## Success Criteria

- **SC-001**: cross_type fixture bundle full graph (toggle on **or** off): no visible/selectable `extends RewardBase` between type nodes `ValidatorChild` and `RewardBase`.
- **SC-001b**: cross_type fixture bundle full graph (toggle on): `approveValidators` -> `_collateralize` `cross_type_call` visible if present in payload.
- **SC-002**: cross_type fixture bundle inter-contract: single Validators -> Oracles semantic edge; no `solidity_import` duplicate.
- **SC-003**: `frontend/src/graph/interContractOverview.test.ts` passes dedupe and full-graph filter cases.
- **SC-004**: Import-only two-contract bundle still shows one `bundle_import` in inter-contract when no `cross_type_*` edge exists.

## Assumptions

- Backend continues emitting both `bundle_import` and `cross_type_call` for extends+import cases; dedupe is intentional view concern.
- Users who need file-level import edges on full graph can use legend or future dedicated toggle (out of scope for v1).
