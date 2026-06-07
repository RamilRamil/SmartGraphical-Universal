# Feature Specification: Function Call Flow View

**Feature Branch**: `010-function-call-flow-view`

**Created**: 2026-05-24

**Status**: Approved concept (product decisions 2026-05-24)

**Input**: On function click, show a dedicated directed call graph of the chains that function participates in (callers upstream, callees downstream), separate from the full compound graph.

## Problem

The full graph mixes contracts, state, modifiers, imports, and many edge kinds. Auditors need a **call-centric** slice: "who calls this function?" and "what does it call?" without mentally filtering the main canvas.

Today:
- Side panel lists metadata and flags (`calls_internal`, etc.) but not a call topology.
- **Focus selection** only works on contract/tile nodes and uses **undirected** 2-hop neighborhood (not call direction).

## Concept

### Call flow graph (CFG view)

A secondary visualization rooted at the **selected function**:

```text
[caller A] --> [caller B] --> [SELECTED: deposit] --> [callee X] --> [callee Y]
```

- **Nodes**: function nodes only (labels = function name; compound = contract/type name).
- **Edges**: directed call semantics only (arrow = caller -> callee).
- **Scope**: derived from the same scan payload as the main graph (no new backend parse in v1).

### Directions (user-controlled)

| Mode | Shows |
|------|--------|
| Upstream | Functions that can reach the root (callers, callers-of-callers, ...) |
| Downstream | Functions reachable from the root (callees, ...) |
| Both | Union of upstream + downstream (**default**) |

**Default on open:** direction = **both**, depth = **2** per direction.

**Expand all:** toolbar button **Expand full chain** switches to unlimited depth in **both** directions (BFS until no new call edges or node cap). User can return to limited depth via depth control or **Reset to default**.

Limited depth remains configurable 1-4 per direction when not in expand-all mode.

### Edge kinds included (v1)

| Kind | Role in call flow |
|------|-------------------|
| `function_to_function` | Intra-contract calls |
| `cross_type_call` | Inherited / parent contract calls |
| `cross_contract_call` | Calls to other contracts (**on by default in v1**) |
| `function_to_object` | Call via named object (optional toggle, off by default) |
| `function_to_system` | Low-level / built-in (optional toggle, off by default) |

**Excluded** from call flow: state read/write, emit, import, modifier rings, events, bundle_import.

### UX placement (recommended)

**Option A (recommended MVP):** Side panel button **"Call flow"** when a function is selected opens a **modal** (or full-width drawer) with its own Cytoscape canvas, toolbar (direction, depth, edge toggles), and **Back to main graph**.

**Option B:** Replace main canvas temporarily (breadcrumb: `Full graph > deposit call flow`). Higher risk of disorientation.

**Option C:** Split pane under the main graph. Heavy on small screens.

**Product decision:** **Modal** (confirmed).

### Interaction with main graph

- Selecting a function on the main graph updates the side panel; user explicitly opens call flow (no auto-open on every click).
- Clicking a node inside call flow highlights the same function on the main graph when modal closes (stretch goal P2).
- Call flow graph is **read-only** for layout (auto dagre); no edit/export in v1.

## User Scenarios

### US1 - Open call flow from selected function (P1)

**Given** full graph with `updateStateAndDeposit` visible, **When** user selects that function and clicks **Call flow**, **Then** a modal shows a directed graph with upstream callers and downstream callees within depth 2.

**Independent Test**: Vitest on `buildCallFlowSubgraph`; manual open on ImportModifierFixture function.

---

### US2 - Control direction and depth (P1)

**Given** call flow modal open, **When** user sets mode to **Downstream only** and depth 1, **Then** only direct callees of the root are shown.

---

### US3 - Cross-contract calls in chain (P1)

**Given** `cross_contract_call` edges exist in payload, **When** call flow opens (default edge set), **Then** callees/callers on other contracts appear when both endpoints are function nodes in the same graph payload.

**Given** user turns off **Show external contract calls**, **When** subgraph rebuilds, **Then** `cross_contract_call` edges are omitted.

---

### US5 - Expand full chain (P1)

**Given** call flow open with default both/depth 2, **When** user clicks **Expand full chain**, **Then** subgraph includes all reachable callers and callees within the scan (both directions) until the expanded node cap or full closure.

**Given** expand-all hit the node cap, **When** graph renders, **Then** banner explains truncation and suggests narrowing direction or depth.

---

### US4 - Empty and heuristic limits (P1)

**Given** a `view` function with no outgoing call edges in payload, **When** downstream mode is selected, **Then** UI shows an explicit empty state (not a broken canvas).

**Given** backend missed a call (regex heuristic), **When** call flow is shown, **Then** a hint notes the view is only as complete as the scan graph.

## Requirements

### Functional Requirements

- **FR-001**: UI MUST offer call flow only when selected node `group === "function"`.
- **FR-002**: Call flow MUST use directed edges consistent with schema (caller -> callee).
- **FR-003**: User MUST choose upstream, downstream, or both; depth 1-4 per direction when limited; **Expand full chain** MUST enable unlimited depth both ways (subject to node cap).
- **FR-007**: Default on modal open: direction **both**, depth **2**, edge kinds include `function_to_function`, `cross_type_call`, and `cross_contract_call`.
- **FR-004**: Subgraph construction MUST be pure client logic from `GraphData` (testable module).
- **FR-005**: Modal MUST be closable without losing main graph selection state.
- **FR-006**: v1 MUST NOT require backend or scan regeneration.

### Non-Goals (v1)

- Full inter-procedural dataflow or dynamic dispatch resolution.
- State variable nodes in the call flow canvas.
- Replacing the main graph layout engine.
- Call flow for non-function nodes (state, contract tile).

## Success Criteria

- **SC-001**: User can answer "who calls X?" and "what does X call?" from the modal without panning the full graph.
- **SC-002**: Subgraph builder unit tests cover upstream/downstream/both, depth cutoff, and expand-all (unlimited depth) with cap.
- **SC-003**: Opening call flow on a typical function completes in under 500 ms for graphs up to 500 functions (client-side).

## Assumptions

- Post spec 007, `function_to_function` and `cross_type_call` directions are caller -> callee.
- Main graph payload already contains needed call edge kinds for the bundle scope.
- English UI labels; ASCII strings in code.

## Product decisions (locked)

| Topic | Decision |
|-------|----------|
| Container | Modal |
| Default view | Both directions, depth 2 |
| Full expansion | Button **Expand full chain**; unlimited depth both ways; higher node cap (e.g. 150) |
| Limited mode cap | 80 nodes |
| `cross_contract_call` | Included by default; optional toggle off |
| Auto-open on click | No; explicit **Call flow** button |
| Modifiers as nodes | No |
| Layout | `dagre` LR preferred |
