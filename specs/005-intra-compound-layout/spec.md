# Feature Specification: Intra-Contract Graph Layout

**Feature Branch**: `005-intra-compound-layout`

**Created**: 2026-05-24

**Input**: Full graph view packs children inside contract (`type`) compounds poorly: heavy overlap, some nodes far from the cluster, compound tiles grow too large (e.g. `ImportModifierFixture.sol`).

## User Scenarios

### US1 - Readable layout inside one contract (P1)

**Given** full graph for a Solidity contract with many functions, state vars, modifiers, and events, **When** the graph renders, **Then** sibling nodes inside the same contract compound do not visually overlap and stay in a compact region without isolated outliers far from the main cluster.

**Why this priority**: Primary audit workflow is reading one contract at a time; unreadable inner layout blocks the tool.

**Independent Test**: Automated layout metrics on a fixed graph fixture (ImportModifierFixture or keeper contract): zero bbox intersections among direct layout cells; no outlier beyond 3x median neighbor distance.

---

### US2 - Smaller contract tile footprint (P1)

**Given** the same contract graph before/after, **When** layout completes, **Then** the bounding box area of the contract compound decreases meaningfully while all labels remain readable.

**Independent Test**: Compare compound bbox area on reference fixture; target at least 25% reduction vs current baseline snapshot.

---

### US3 - Stable bundle / multi-contract view (P2)

**Given** a bundle with multiple contracts, **When** full graph is shown, **Then** outer placement of contract compounds remains force-directed and readable; inner layout of each contract is independent and reproducible (same graph yields same inner positions).

**Independent Test**: Two layout runs on same payload produce identical positions for intra-compound nodes (`randomize: false`).

---

### US4 - Inter-contract overview unchanged (P2)

**Given** inter-contract overview mode, **When** user toggles view, **Then** existing overview layout behavior is preserved (no regression in contract-to-contract spacing).

## Edge Cases

- Contract with only functions (no state/events).
- Functions with multiple `modifier_ring` wrapper compounds.
- Very long function names (label-sized nodes).
- C-style graphs using `tile` compounds instead of `type`.
- Hidden legend nodes / Show imports toggles affect visibility but not stored layout positions.

## Requirements

### Functional Requirements

- **FR-001**: Full graph MUST lay out intra-compound children with a deterministic strategy (not global force-only on all nodes).
- **FR-002**: Layout MUST group semantic kinds inside a contract (state, modifier, function, event/custom_error) to reduce cross-kind edge pull.
- **FR-003**: Outer layout MUST position only top-level compounds (`type`, `tile`, loose externals); inner positions MUST remain fixed during outer pass.
- **FR-004**: Algorithm MUST be tunable via constants (cell spacing, tier order) without backend changes.
- **FR-005**: Inter-contract overview MUST keep current layout path.
- **FR-006**: Vitest coverage for position assignment pure functions and overlap/outlier metrics.
- **FR-007**: State variables MUST be placed on a single horizontal row inside each compound.
- **FR-008**: Modifiers MUST be placed in the top-left corner, separate from the main vertical stack.
- **FR-009**: Functions with `public` or `external` visibility MUST appear above the state row; other functions below.
- **FR-010**: Events and `custom_error` nodes MUST appear in a column to the right of the main stack.
- **FR-011**: When a function band has more than six nodes, it MUST split into two sub-rows; higher effective degree (including entrypoint bonus) MUST be closer to the state line.
- **FR-012**: Intra-compound positions MUST come from deterministic grid seeds only (no per-tier fcose) so the sandwich geometry is preserved.

### Key Entities

- **Compound root**: `type` or `tile` node containing contract members.
- **Layout cell**: One grid slot (function + its modifier rings, or standalone state/modifier/event node).
- **Outer layout**: Force-directed placement of compound roots.

## Success Criteria

- **SC-001**: Reference fixture has zero overlapping layout cells inside each contract compound.
- **SC-002**: Reference compound bbox area improves by >= 25% vs pre-change baseline.
- **SC-003**: No intra-compound outlier nodes beyond 3x median nearest-neighbor distance inside same compound.
- **SC-004**: `frontend` unit tests pass; inter-contract overview tests unchanged.

## Assumptions

- View-layer only; graph JSON schema unchanged.
- `cytoscape-fcose` already in dependencies may be used for outer layout; no new npm packages.
- Modifier rings remain visual compounds in v1 (no schema change to flatten rings).

## Product decisions (sandwich layout, 2026-05-24)

| Topic | Decision |
|-------|----------|
| Modifier corner | Top-left |
| State | Single horizontal line |
| Functions | Above/below state by visibility; max 6 per sub-row |
| Entrypoints | Degree bonus pulls toward state |
| Events | Right column |
| Inner fcose | Disabled (grid only) |

## Out of Scope

- Edge routing / label placement optimization.
- Animated layout transitions.
- User-draggable manual layout persistence.
- Horizontal seriation by state connectivity (future).
