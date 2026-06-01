---
description: "Task list for feature 012 — Findings Overlay on the Interactive Graph"
---

# Tasks: Findings Overlay on the Interactive Graph

**Input**: Design documents from `specs/012-findings-graph-overlay/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED for the correlation module (constitution Principle VII; the
spec asks for Vitest coverage across languages). Component wiring is verified
manually via quickstart.

**Repo root for all paths**: `SmartGraphical/`. Frontend commands run from
`frontend/`. This feature touches **only `frontend/`** — no backend changes.

## Implementation status (2026-06-01)

**MVP shipped (US1 + US2, both P1)** — verified by `npm run typecheck` (clean),
`npm run test` (74 Vitest tests green incl. 7 new for `correlateFindings`), and
`eslint` (clean). Done: T001-T005, T007-T009, T015.

**Remaining (need browser verification or are P2/P3):**
- T006 legend entry for the finding overlay (typecheck part done; legend JSX not added).
- T010 manual US2 verification in the running app (quickstart §3).
- T011-T012 US3 "only nodes with findings" filter (P2).
- T013-T014 US4 node-selection findings list in the side panel (P3).
- T016 back-compat doc note (props are already optional + guarded).

The static-analysis level is verified; the Cytoscape overlay halo, the `[count]`
label suffix, and finding->node focus need a manual run (`npm run dev` against the
API) to confirm visually.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: can run in parallel (different files, no dependency on incomplete tasks)
- **[Story]**: US1–US4 from spec.md

---

## Phase 1: Setup

- [X] T001 Baseline: from `frontend/`, run `npm install` if needed, then `npm run test` and `npm run typecheck` to confirm the existing Vitest suite and types are green before changes.

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ The correlation module is consumed by US1–US4; it must exist first.**

- [X] T002 [P] Write Vitest tests in `frontend/src/graph/correlateFindings.test.ts` per `specs/012-findings-graph-overlay/contracts/correlation-module.md` matrix: Solidity (`function` node), C (`tile` container), Rust function, mixed-confidence aggregation (count + maxConfidence), multi-match, and unmapped.
- [X] T003 Implement `frontend/src/graph/correlateFindings.ts` — `Confidence`, `NodeFindingSummary`, `FindingsCorrelation`, and `correlateFindings(findings, nodes)` satisfying rules R1–R7 (match on `type_name`/`label`, no node-id reconstruction; high>medium>low; unmapped collected) until T002 passes.

**Checkpoint**: pure correlation available and tested.

---

## Phase 3: User Story 1 - See where findings cluster (Priority: P1) 🎯 MVP

**Goal**: nodes that own findings show a count badge and a confidence-derived color (low muted, high prominent).

**Independent Test**: quickstart §2 — finding-owning nodes are marked, others are not.

- [X] T004 [US1] Extend `frontend/src/components/GraphView.tsx`: add optional `findingSummaries?: ReadonlyMap<string, NodeFindingSummary>` prop; in the cytoscape stylesheet, render a finding-count badge and a confidence-ramp node style (high = most prominent, medium, low = muted) for nodes present in the map (graphview-props.md B1/B5).
- [X] T005 [US1] In `frontend/src/pages/ScanDetailPage.tsx`, memoize `correlateFindings(findings, graphData.nodes)` when both are available and pass `correlation.byNodeId` as `findingSummaries` to `GraphView`.
- [ ] T006 [US1] Add a legend entry for the finding badge / confidence ramp in `GraphView.tsx`; verify US1 per quickstart §2 and `npm run typecheck`.

**Checkpoint**: spatial risk map visible — MVP increment.

---

## Phase 4: User Story 2 - Jump from a finding to its node (Priority: P1)

**Goal**: clicking a finding focuses its node on the Graph tab; unmapped findings say so.

**Independent Test**: quickstart §3 — mapped finding focuses its node; unmapped shows an explicit message.

- [X] T007 [US2] Add optional `focusNodeId?: string | null` prop to `frontend/src/components/GraphView.tsx`: on change to an id present in the graph, center and highlight that node (reuse the cytoscape `Core`/selection); no-op when absent (graphview-props.md B2).
- [X] T008 [P] [US2] Add an optional "Show on graph" action (callback prop) to `frontend/src/components/FindingCard.tsx`.
- [X] T009 [US2] Wire navigation in `frontend/src/pages/ScanDetailPage.tsx`: on a finding's "Show on graph", resolve `correlation.nodeIdsForFindingIndex(i)`; if non-empty → `setTab("graph")` + set `focusNodeId` to the first id; if empty → show an explicit "this finding could not be located on the graph" message; hide/disable the action when no graph is available (FR-005, FR-010).
- [ ] T010 [US2] Verify US2 per quickstart §3.

**Checkpoint**: one-click finding → structure.

---

## Phase 5: User Story 3 - Filter to the suspicious surface (Priority: P2)

**Goal**: show only finding-owning nodes (optionally plus neighbors), with an empty state.

**Independent Test**: quickstart §4.

- [ ] T011 [US3] Add to `frontend/src/components/GraphView.tsx` a "Only nodes with findings" toggle (enabled only when `findingSummaries` is non-empty) and an "include neighbors" toggle; hide non-matching nodes; show an explicit empty state when nothing qualifies (graphview-props.md B3).
- [ ] T012 [US3] Verify US3 per quickstart §4.

**Checkpoint**: large graphs reducible to the concern surface.

---

## Phase 6: User Story 4 - A node's findings from the graph (Priority: P3)

**Goal**: selecting a node lists its findings in the side panel.

**Independent Test**: quickstart §5.

- [ ] T013 [US4] In `frontend/src/components/GraphView.tsx` side panel, when the selected node has a `findingSummaries` entry, list its findings (title, category, confidence); otherwise state it has none. Add any needed panel styles in `frontend/src/styles.css` (graphview-props.md B4).
- [ ] T014 [US4] Verify US4 per quickstart §5.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T015 [P] From `frontend/`, run `npm run test` and `npm run typecheck` — all green, including existing graph modules (no regression).
- [ ] T016 [P] Confirm back-compat (B5): with neither `findingSummaries` nor `focusNodeId` set, `GraphView` renders exactly as before; note the new optional props in a `GraphView.tsx` doc comment.

---

## Dependencies & Execution Order

- **Setup (T001)** → none.
- **Foundational (T002→T003)** → blocks all user stories. T002 (tests) first, T003 implements until green.
- **US1 (T004–T006)** → after Foundational. T005 establishes the memoized correlation in `ScanDetailPage` that US2/US3 reuse.
- **US2 (T007–T010)** → after Foundational; reuses US1's correlation in `ScanDetailPage`. T007 (GraphView) and T008 (FindingCard) are parallel (different files); T009 depends on both + the correlation.
- **US3 (T011–T012)** → after Foundational + US1 (consumes `findingSummaries`).
- **US4 (T013–T014)** → after Foundational + US1.
- **Polish (T015–T016)** → after all stories; parallel.

## Parallel Opportunities

- T007 (GraphView `focusNodeId`) and T008 (FindingCard action) — different files.
- T015 and T016 — independent checks.

## Implementation Strategy

- **MVP = US1 + US2 (both P1)**: see findings on the graph and jump to them — the
  core fusion of the two pillars. Ship and validate before US3/US4.
- **Incremental**: US1 → US2 → US3 (filter) → US4 (node panel) → Polish.
- **Module-first**: T002/T003 deliver the tested pure correlation; every UI task
  then consumes it, keeping components thin and logic covered.
