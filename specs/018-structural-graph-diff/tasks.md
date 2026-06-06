---
description: "Task list for feature 018 — Structural graph diff between two scans"
---

# Tasks: Structural graph diff between two scans

> **Status (2026-06-06): backend slice COMPLETE (US1+US2).** All 12 tasks [X].
> New pure `services/graph_diff.py::diff_graph_payloads` (nodes by canonical id;
> edges by `(source,target,kind)`, positional `edge:N` ignored; deterministic
> sorted output; `graph_available=False` when either side has no graph),
> `HistoryService.diff_graphs` (reuses get_graph + the findings-diff
> same-artifact/not-found guards), and route `GET /scans/{id}/graph-diff/{other}`.
> 15 new tests (pure 11, history 4 incl. no-graph/mismatch/not-found, HTTP 2).
> Full suite **513 passed**, 0 failed; findings diff + existing endpoints
> unchanged. HTTP mismatch code is `diff_artifact_mismatch` (the project's actual
> ERROR_DIFF_MISMATCH value).
>
> **US3 (web DiffPage visualization) — DONE 2026-06-06.** Added frontend
> `GraphDiff*` types, `api.diffGraphs` client, `useGraphDiff` hook, pure
> `graph/graphDiffSummary.ts` (5 Vitest), and a `GraphDiffSection` in
> `DiffPage.tsx` (counts + grouped added/removed/changed nodes + added/removed
> edges; handles graph_available=false and identical-graph). Frontend: typecheck
> clean, **81 vitest passed** (5 new), `vite build` ok. CSS classes
> `sg-diff__subsection`/`sg-section__subtitle`/`sg-list` not added — `styles.css`
> is the user's uncommitted WIP, left untouched (renders functional, maybe
> unstyled). **Block D is now fully closed.**

**Input**: Design documents from `specs/018-structural-graph-diff/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/graph-diff.md, quickstart.md

**Tests**: Targeted tests requested (Principle VII + FR-008): pure-diff unit
tests, a HistoryService integration test, and an HTTP contract test.

**Scope of this slice**: US1 (pure core + history method) and US2 (HTTP endpoint).
US3 (web DiffPage visualization) is a separate frontend increment — NOT in this
slice.

**Hard rules**: additive only — do NOT change the findings diff, the stored graph
payload shape, rule output, or existing endpoints (FR-007). Reuse the existing
`ERROR_DIFF_MISMATCH` / `ERROR_NOT_FOUND` contract.

**Paths** relative to `SmartGraphical/`. Python = `.venv/bin/python` (`PYTHONPATH=.`).

---

## Phase 1: Setup

- [X] T001 Confirm baseline: `.venv/bin/python -m pytest -q` (expect 498 passed,
  12 skipped post-017).

---

## Phase 2: Foundational

- [X] T002 Create `smartgraphical/services/graph_diff.py` with module docstring
  and a `_graph_section(payload)` helper that defensively returns
  `(nodes, edges)` from `payload["model_summary"]["graph"]`, tolerating
  `None`/missing keys (returns `([], [])`).

---

## Phase 3: User Story 1 — Structural graph diff core + history (P1) 🎯 MVP

**Goal**: pure `diff_graph_payloads` + `HistoryService.diff_graphs`.

**Independent test**: pure-diff and history integration tests green.

- [X] T003 [US1] Implement `diff_graph_payloads(payload_a, payload_b)` in
  `services/graph_diff.py` per data-model.md: node identity = `id`, signature =
  `(group,label,kind)` → added/removed/changed (changed carries before/after);
  edge identity = `(source,target,kind)` (ignore positional `edge:N`) →
  added/removed; include all `*_count` + `unchanged_node_count`; set
  `graph_available=False` when either side lacks a graph; sort all lists by their
  identity key for determinism.
- [X] T004 [P] [US1] Add `tests/unit/test_graph_diff.py`: synthetic payloads cover
  added node, removed node, changed node (group/label/kind), added edge, removed
  edge, positional-edge-id-only change ⇒ unchanged (SC-005), identical graphs ⇒
  all empty (SC-002), missing/None payload ⇒ `graph_available=False` (FR-005),
  and deterministic sorted output.
- [X] T005 [US1] Add `HistoryService.diff_graphs(scan_a_id, scan_b_id)` in
  `services/history_service.py`: scan lookup (`ERROR_NOT_FOUND`), same-artifact
  guard (`ERROR_DIFF_MISMATCH`) exactly as `diff_scans`; `get_graph` each side;
  call `diff_graph_payloads`; augment result with `scan_a_id`, `scan_b_id`,
  `artifact_id`.
- [X] T006 [P] [US1] Add `tests/unit/test_history_service_graph_diff.py`
  (mirror the `test_history_service.py` setUp): two `run_all` scans of the same
  fixture diff cleanly; different-artifact ⇒ `ERROR_DIFF_MISMATCH`; missing scan
  ⇒ `ERROR_NOT_FOUND`; a single-rule `run_analysis` scan (no graph) ⇒
  `graph_available=False`.
- [X] T007 [US1] Verify US1: `pytest tests/unit/test_graph_diff.py
  tests/unit/test_history_service_graph_diff.py -q` green.

**Checkpoint**: graph diff core + persistence done, fully tested.

---

## Phase 4: User Story 2 — Graph diff over HTTP (P2)

**Goal**: stable endpoint mirroring the findings-diff route.

- [X] T008 [US2] Add `GET /scans/{scan_id}/graph-diff/{other_id}` in
  `interfaces/http/routes.py` next to `diff_scans`, delegating to
  `service.diff_graphs(scan_id, other_id)`.
- [X] T009 [P] [US2] Add `tests/integration/test_http_graph_diff.py` (mirror the
  existing HTTP diff test): endpoint returns the graph-diff JSON for two
  same-artifact scans; mismatched artifacts return the same error contract as the
  findings-diff endpoint.
- [X] T010 [US2] Verify US2: `pytest tests/integration/test_http_graph_diff.py -q`
  green.

**Checkpoint**: graph diff queryable over HTTP.

---

## Phase 5: Polish & cross-cutting verification

- [X] T011 [P] No-regression: `pytest tests/unit/test_history_service.py
  tests/integration/test_http_contract.py -q` green (findings diff + existing
  endpoints unchanged).
- [X] T012 Final regression: `.venv/bin/python -m pytest -q` green (≥ 498 + new
  tests, 0 failed). Mark tasks [X] and add a status note. Note US3 (frontend) as
  the remaining increment for full block-D closure.

---

## Phase 6: User Story 3 — Graph diff in the web DiffPage (frontend)

- [X] T013 [US3] Frontend `GraphDiff*` types (`api/types.ts`), `api.diffGraphs`
  (`api/client.ts`), `useGraphDiff` + `queryKeys.graphDiff` (`api/hooks.ts`).
- [X] T014 [US3] Pure `frontend/src/graph/graphDiffSummary.ts` + `.test.ts` (5
  Vitest): total/empty/group-by-group/describe-edge/changed-fields.
- [X] T015 [US3] `GraphDiffSection` in `frontend/src/pages/DiffPage.tsx` wired via
  `useGraphDiff` (counts + grouped node lists + edge lists; graph_available=false
  and identical-graph handled).
- [X] T016 [US3] Verify: `npm run typecheck` clean, `npm test` 81 passed,
  `npm run build` ok.

## Dependencies & ordering

- Setup (T001) → first.
- Foundational (T002) → before US1.
- US1 (T003–T007): T003→(T004 [P])→T005→(T006 [P])→T007. T004 depends on T003;
  T006 depends on T005.
- US2 (T008–T010) → after US1 (route calls `diff_graphs`).
- Polish (T011–T012) → last; T011 is [P].

## Implementation strategy

- **MVP = US1**: the pure diff + history method is the structural capability and is
  fully testable offline. US2 exposes it over HTTP. US3 (DiffPage UI) is a
  separate frontend increment that, once done, closes block D.
