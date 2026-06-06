# Feature Specification: Unify CLI graphviz and web renderers on one graph projection

**Feature Branch**: `017-unify-cli-graphviz`

**Created**: 2026-06-06

**Status**: Draft

**Input**: User description: "Unify CLI (graphviz) and web (cytoscape) renderers to one graph-model source. Today the CLI graphviz renderer re-derives the graph from the raw NormalizedAuditModel with its own node-id scheme (func_X_Y), while the web renders the canonical projection from model_graph_to_dict (type:/tile:/function ids, bundle edges, write paths). Make both consume one shared graph projection so the two pillars cannot drift."

## Overview

SmartGraphical renders the code graph two different ways from the same
`NormalizedAuditModel`:

- **Web (cytoscape)** consumes the canonical, rich projection produced by
  `serializers.model_graph_to_dict(model)` — nodes/edges with stable ids
  (`type:`, `function:`, `tile:` for C, external classes), canonical groups and
  edge kinds, bundle edges, write-path derivation, and a validation/normalization
  pass. This is the projection the findings overlay, diff, and history all key on.
- **CLI (graphviz)** in `core/graph.py::GraphBuilder.render` re-walks
  `model.types` and `model.call_edges` from scratch with a **separate** node-id
  scheme (`func_<type>_<name>`, `var_…`, `obj_…`, `sysfunc_…`) and its own
  edge-kind handling, then renders a PNG.

These two graph constructions have drifted: different node identities, different
node sets (e.g. the CLI scheme has no `tile:`/bundle concept), and independently
maintained edge-kind logic. Any graph improvement must be made twice, and the two
pillars can silently diverge — directly against Constitution Principle V (the
findings and graph pillars must reference the same entities).

This feature makes the CLI graphviz renderer consume the **same** canonical graph
projection the web uses, so there is a single source of truth for graph
structure. graphviz becomes a thin "render this canonical graph dict to PNG"
step; cytoscape stays "render this canonical graph dict in the browser."

## Clarifications

### Session 2026-06-06

- Q: The CLI PNG currently has no automated test and graphviz is an optional
  dependency. Is changing the PNG's visual output acceptable? → A: Yes. The PNG
  is visual-only and untested; the goal is that it reflects the **same** node/edge
  model as the web. Visual restyling to fit graphviz is expected and acceptable;
  the binding requirement is structural parity (same node ids/groups/edge kinds),
  not pixel preservation.
- Q: Must graceful degradation when graphviz is absent be preserved? → A: Yes,
  unchanged — a missing graphviz package must never crash a scan (Constitution
  Technology Constraints).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - One graph projection feeds both renderers (Priority: P1)

A maintainer who improves the graph (adds an edge kind, fixes node grouping,
adds bundle handling) edits the canonical projection once and both the web graph
and the CLI PNG reflect the change — they can no longer disagree about what nodes
and edges exist.

**Why this priority**: This is the whole point of the feature and the Principle V
guarantee. It is the MVP: the CLI renderer must derive its nodes and edges from
`model_graph_to_dict` (or an equivalent single shared projection), not from a
parallel walk of the raw model.

**Independent Test**: For a representative Solidity, C, and Rust fixture, the set
of node identities and edges the CLI renderer draws is derived from the same
`model_graph_to_dict(model)` output the web uses — verifiable by asserting the
CLI renderer is handed the canonical graph dict (same node ids/groups/edge kinds)
rather than constructing `func_X_Y` ids.

**Acceptance Scenarios**:

1. **Given** a Solidity contract, **When** the CLI renders the graph, **Then**
   the nodes/edges it renders correspond one-to-one (by id, group, kind) to the
   nodes/edges in `model_graph_to_dict(model)` for that contract.
2. **Given** a C translation unit (which has `tile:` nodes in the canonical
   projection), **When** the CLI renders, **Then** the CLI graph includes those
   canonical nodes/edges (no separate, divergent C handling).
3. **Given** the same model, **When** comparing the CLI graph's node-id set with
   the web graph's node-id set, **Then** they are equal.

---

### User Story 2 - graphviz rendering still works and degrades gracefully (Priority: P2)

A user running the CLI with `task = 99` or run-all still gets a PNG when graphviz
is installed, and a clean, non-crashing message when it is not.

**Why this priority**: The deliverable must not regress the existing CLI render
behaviour or the optional-dependency contract. Lower than US1 because it is a
preservation requirement, not the core change.

**Independent Test**: With graphviz installed, the CLI render path produces a
`.gv`/PNG artifact without error for each language fixture; with graphviz absent
(simulated), the render path prints the existing graceful message and returns
without raising.

**Acceptance Scenarios**:

1. **Given** graphviz is available, **When** the CLI render path runs on a
   fixture, **Then** it completes without error and emits the graph artifact.
2. **Given** graphviz is unavailable, **When** the CLI render path runs, **Then**
   it prints the not-installed message and returns (no exception, scan not
   crashed).

---

### Edge Cases

- **Bundle graphs**: the canonical projection for bundles includes bundle edges
  (`bundle_import`, `tile_to_tile`, etc.). The CLI renderer must render whatever
  groups/kinds the canonical projection emits, including ones the old `func_X_Y`
  scheme never had, without special-casing.
- **Unknown/new groups or edge kinds**: the renderer must handle the canonical
  group/kind vocabulary in a data-driven way (a mapping from canonical group →
  graphviz shape, canonical kind → edge style) so a new kind degrades to a
  sensible default rather than being silently dropped.
- **External/unresolved nodes**: external/unknown nodes present in the canonical
  projection must appear in the CLI graph too (Principle II — don't hide boundary
  signals).
- **graphviz missing**: unchanged graceful message; never raise.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The CLI graphviz renderer MUST derive the nodes and edges it draws
  from the canonical graph projection (`serializers.model_graph_to_dict(model)`
  or the `model_summary_to_dict` graph it wraps), not from an independent walk of
  `model.types` / `model.call_edges`.
- **FR-002**: The node-id set and edge set the CLI renders MUST equal the
  canonical projection's node-id set and edge set for the same model (structural
  parity with the web pillar).
- **FR-003**: The renderer MUST map canonical node groups (e.g. `type`,
  `function`, `state`, `external`, `modifier`, `event`, `tile`) to graphviz
  visuals and canonical edge kinds to graphviz edge styles via an explicit,
  data-driven mapping, with a sensible default for any unmapped group/kind (no
  silent drops).
- **FR-004**: graphviz MUST remain an optional dependency: when it is not
  installed, the render path MUST print the existing not-installed message and
  return without raising (no crash, scan unaffected).
- **FR-005**: The change MUST NOT alter the web/cytoscape graph payload
  (`model_graph_to_dict` / `model_summary_to_dict` output) — those JSON shapes
  remain byte-for-byte identical (no regression to the web pillar, history, or
  diff).
- **FR-006**: The change MUST NOT alter findings, rule output, or any non-graph
  CLI/web behaviour.
- **FR-007**: The parallel `func_X_Y` / `var_` / `obj_` / `sysfunc_` node-id
  construction in `core/graph.py` MUST be removed (it is the duplication being
  eliminated), leaving graphviz as a thin renderer over the canonical dict.
- **FR-008**: New behaviour MUST be covered by targeted tests (Principle VII):
  at minimum, a test asserting CLI/web node-id parity from the canonical
  projection, and a test asserting graceful degradation when graphviz is absent.

### Key Entities

- **Canonical graph projection**: the nodes/edges dict from
  `model_graph_to_dict(model)` — the single source of truth for graph structure
  (ids, groups, kinds), already consumed by the web.
- **Graph PNG renderer**: a thin component that takes the canonical projection +
  an output label and emits a graphviz PNG, applying a group→shape / kind→style
  mapping. Degrades gracefully without graphviz.
- **Group/kind visual mapping**: the explicit table translating canonical node
  groups and edge kinds into graphviz shapes/colors/edge styles.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For Solidity, C, and Rust fixtures, the CLI renderer's node-id set
  equals the web canonical projection's node-id set (parity test passes).
- **SC-002**: The web graph payload (`model_graph_to_dict` /
  `model_summary_to_dict`) is byte-for-byte unchanged before and after the
  feature for all existing fixtures (no web regression).
- **SC-003**: The full backend test suite stays green (≥ 493 passed, 0 failed),
  plus the new graph-parity and graceful-degradation tests.
- **SC-004**: Graph-structure construction logic exists in exactly one place; the
  duplicate `func_X_Y` scheme in `core/graph.py` is gone (verifiable by grep).
- **SC-005**: With graphviz absent, the CLI render path returns cleanly (no
  exception) and a scan still completes.

## Assumptions

- The CLI PNG has no golden/automated visual baseline today and graphviz is
  optional; therefore changing the PNG's appearance is acceptable as long as the
  underlying node/edge model matches the web (structural parity, not pixels).
- `model_graph_to_dict` is the canonical projection to standardize on; it already
  handles all three languages, bundles, write paths, and validation. This feature
  does not redesign that projection — it makes the CLI consume it.
- Graph **diff** (the third block-D sub-feature) is out of scope here; it will
  benefit from this single projection but is specified separately.
- Frontend cytoscape code is not changed by this feature (it already consumes the
  canonical projection); the work is backend (`core/graph.py` + wiring).
