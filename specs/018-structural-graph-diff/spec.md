# Feature Specification: Structural graph diff between two scans

**Feature Branch**: `018-structural-graph-diff`

**Created**: 2026-06-06

**Status**: Draft

**Input**: User description: "Structural graph diff. Compare the graphs of two scans of the same artifact and report which nodes and edges were added, removed, or changed. Mirror the existing findings diff (diff_scans) and reuse the canonical graph projection now shared by both renderers (feature 017)."

## Overview

SmartGraphical already diffs **findings** between two scans of the same artifact
(`HistoryService.diff_scans`, surfaced at `/scans/{id}/diff/{other}` and the web
DiffPage). The second product pillar — the interactive code graph — has no diff:
an auditor cannot see how the *structure* of a contract/program changed between
two versions (new functions, removed state, rewired calls).

Every scan already persists its graph payload (`graph.json`, the output of
`web_api.graph`, retrievable via `HistoryService.get_graph`). With feature 017 the
graph node identities are canonical and stable (`type:`, `function:`, `state:`,
`tile:`, `external:` …) and shared by both renderers, which makes a meaningful
structural diff possible: nodes can be matched by their stable `id` across scans.

This feature adds a structural graph diff: given two scans of the same artifact,
report nodes added / removed / changed and edges added / removed, mirroring the
findings-diff shape and guard rules.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Structural graph diff core (Priority: P1)

An auditor (via the API or a future UI) compares two scans of the same artifact
and gets a structured summary of how the graph changed: which nodes appeared,
disappeared, or changed group/label/kind, and which edges appeared or disappeared.

**Why this priority**: This is the feature. It is the reusable core other surfaces
build on, and it is independently testable purely from two graph payloads.

**Independent Test**: A pure diff function over two graph payloads returns the
correct added/removed/changed node sets (keyed by canonical `id`) and
added/removed edge sets (keyed by `(source, target, kind)`), verifiable on
synthetic payloads and on two real scans of the same fixture.

**Acceptance Scenarios**:

1. **Given** two graph payloads where scan B adds a function node, **When** diffed,
   **Then** that node id appears in `added_nodes` and nowhere else.
2. **Given** scan B removes a state node, **When** diffed, **Then** that id appears
   in `removed_nodes`.
3. **Given** a node whose `label`/`group`/`kind` changed but `id` is the same,
   **When** diffed, **Then** it appears in `changed_nodes` (with before/after),
   not in added or removed.
4. **Given** an edge with the same `(source, target, kind)` in both scans but a
   different positional `edge:N` id, **When** diffed, **Then** it is treated as
   unchanged (edge identity is semantic, not positional).
5. **Given** `HistoryService.diff_graphs(scan_a, scan_b)` for two scans of the
   same artifact, **When** called, **Then** it loads both stored graphs and
   returns the diff; for scans of different artifacts it raises the same
   mismatch error as the findings diff.

---

### User Story 2 - Graph diff over HTTP (Priority: P2)

A client retrieves the graph diff for two scans via a stable JSON endpoint,
alongside the existing findings-diff endpoint.

**Why this priority**: Makes the core usable by the web app and automation without
a UI. Lower than US1 because it is a thin wrapper over the core.

**Independent Test**: `GET /scans/{scan_id}/graph-diff/{other_id}` returns the
diff JSON for two same-artifact scans and the standard error for mismatched
artifacts / missing scans.

**Acceptance Scenarios**:

1. **Given** two same-artifact scans with graphs, **When** the endpoint is
   called, **Then** it returns the graph-diff JSON (added/removed/changed counts
   and lists).
2. **Given** scans of different artifacts, **When** called, **Then** it returns
   the same mismatch error contract as `/scans/{id}/diff/{other}`.

---

### User Story 3 - Graph diff in the web DiffPage (Priority: P3)

An auditor sees the graph diff visually in the existing DiffPage (e.g. a summary
of added/removed/changed nodes and edges, optionally highlighting them on the
graph).

**Why this priority**: Highest end-user value but the largest surface; the core +
API (US1/US2) deliver the capability and are independently shippable first. This
story is a separate frontend increment.

**Independent Test**: DiffPage shows the graph-diff summary fetched from the US2
endpoint for two selected scans; Vitest covers the rendering/transform logic.

**Acceptance Scenarios**:

1. **Given** two scans selected in DiffPage, **When** the graph-diff loads,
   **Then** the user sees counts and lists of added/removed/changed nodes/edges.

---

### Edge Cases

- **Missing graph payload**: a scan created by a single-rule run has no
  `graph.json`. The diff MUST handle a missing graph on either side gracefully
  (clear, non-crashing result indicating the graph is unavailable), not raise an
  unexpected error.
- **Bundle graphs**: bundle scans have a merged graph; the same id-based node
  matching and `(source,target,kind)` edge matching apply unchanged.
- **Positional edge ids**: `edge:N` ids are positional and unstable; they MUST
  NOT be used as edge identity (only `(source, target, kind)`).
- **Same artifact guard**: like the findings diff, graph diff is only allowed
  between two scans of the same artifact.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a pure function that, given two graph
  payloads, returns nodes added / removed / changed (keyed by canonical node
  `id`) and edges added / removed (keyed by `(source, target, kind)`), plus
  counts.
- **FR-002**: A node MUST be classified as **changed** when its `id` exists in
  both scans but a tracked attribute (`group`, `label`, or `kind`) differs;
  changed entries MUST carry the before and after values.
- **FR-003**: Edge identity MUST be the semantic triple `(source, target, kind)`,
  never the positional `edge:N` id.
- **FR-004**: `HistoryService.diff_graphs(scan_a_id, scan_b_id)` MUST load both
  scans' stored graph payloads and return the diff, applying the same
  same-artifact guard and not-found error contract as `diff_scans`.
- **FR-005**: A missing graph payload on either scan MUST yield a clear,
  non-crashing result (e.g. empty diff plus a flag/notice), not an exception.
- **FR-006**: The graph diff MUST be exposed over HTTP at a stable endpoint
  (`GET /scans/{scan_id}/graph-diff/{other_id}`) returning JSON-safe output.
- **FR-007**: The feature MUST NOT change the findings diff, the stored graph
  payload shape, rule output, or any existing endpoint.
- **FR-008**: New behaviour MUST be covered by targeted tests (Principle VII):
  pure-diff unit tests (incl. the positional-edge-id case) and a HistoryService
  integration test, plus an HTTP contract test for the endpoint.

### Key Entities

- **Graph payload**: stored `web_api.graph` output; nodes/edges live at
  `model_summary.graph.{nodes,edges}`.
- **Graph diff result**: `{ added_nodes, removed_nodes, changed_nodes,
  added_edges, removed_edges, *_count, graph_available }` — JSON-safe, mirroring
  the findings-diff shape.
- **Node identity**: canonical `id`. **Edge identity**: `(source, target, kind)`.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For two scans of the same fixture differing by a known structural
  change, the diff reports exactly the expected added/removed/changed nodes and
  added/removed edges.
- **SC-002**: Re-running the graph diff on identical graphs yields zero
  added/removed/changed (only unchanged), deterministically.
- **SC-003**: The endpoint returns the same mismatch/not-found error contract as
  the findings diff for invalid inputs.
- **SC-004**: The full backend suite stays green (≥ 498 passed, 0 failed) plus the
  new graph-diff tests; the stored graph payload and findings diff are unchanged.
- **SC-005**: Edge matching ignores positional `edge:N` ids (proven by a test
  where only the positional id differs → unchanged).

## Assumptions

- Canonical node ids (feature 017) are stable enough across scans of the same
  artifact to serve as node identity; structural changes are expressed as
  add/remove/change of those ids.
- The web DiffPage visualization (US3) is a separate frontend increment; US1+US2
  (core + API) are the independently shippable backend deliverable.
- "Changed" tracks `group`/`label`/`kind` only; deeper per-attribute diffing
  (fact fields, line numbers) is out of scope for this feature.
- Graph diff reuses the existing same-artifact guard and not-found errors from the
  findings diff rather than inventing new error codes.
