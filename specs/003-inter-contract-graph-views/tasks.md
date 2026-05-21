# Tasks: Inter-Contract Graph Views

**Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

**Status**: Complete (2026-05-21); hotfix US2 (2026-05-21)

## Phase 1 - View filtering (US1, US2)

- [x] T001 [US1] Add `filterFullGraphEdges()` and edge kind constants in `frontend/src/graph/interContractOverview.ts`
- [x] T002 [US1] Wire `displayGraph` to `filterFullGraphEdges(graph, showCrossContractCalls)` when not inter-contract
- [x] T003 [US1] Update `applyGraphVisibility` to hide `INTER_CONTRACT_EDGE_KINDS` on full graph; external kinds gated by toggle
- [x] T004 [US2] Rename toolbar control to Show/Hide **external contract calls**; disable in inter-contract with tooltip
- [x] T005 [US1] Filter cytoscape elements (not only `hide()`); ignore hidden edges on tap; `connectedEdges().filter(visible)`
- [x] T006 [US1] Clear `selectedEdge` when returning to full graph if kind is inter-contract-only

## Phase 2 - Inter-contract dedupe (US3, US4)

- [x] T007 [US3] In `toInterContractOverviewGraph()`, drop `bundle_import`/`tile_to_tile` when same pair has `cross_type_*` edge
- [x] T008 [US3/US4] Add Vitest: dedupe extends+import pair; keep import-only pair
- [x] T009 [US3] Update edge legend guide: cross-type shown in Inter-contract view

## Phase 3 - Docs

- [x] T010 Spec Kit artifacts under `specs/003-inter-contract-graph-views/`
- [x] T011 Update `.cursor/rules/specify-rules.mdc` SPECKIT pointer

## Hotfix - Show cross-contract calls (US2)

- [x] T012 [US2] `filterFullGraphEdges`: include `INTER_CONTRACT_EDGE_KINDS` when toggle on (keeper `extends` visible)
- [x] T013 [US2] Split `structureGraph` vs `displayGraph`; stop rebuilding Cytoscape on toggle
- [x] T014 [US2] `edgeIdsDroppedAsRedundantBundleLinks` + visibility for duplicate `bundle_import`
- [x] T015 [US2] Vitest `filterFullGraphEdges` on/off; restore toolbar label **Show cross-contract calls**

## Hotfix - Toggle visible edges (US2 follow-up)

- [x] T016 [US2] Apply visibility on Cytoscape init (no flash of hidden edges)
- [x] T017 [US2] `core.fit(crossContractEdges)` when toggle turns on (edges were off-screen after `.hide()`)
- [x] T018 [US2] Re-enable legend bucket `edge_cross_type` when turning toggle on
- [x] T019 [US2] Fix `graphVisibilityOpts` order (`focusNodeIds` before opts memo)

## Hotfix - Type-level extends never on full graph (US1 / FR-001)

- [x] T020 [US1] `isTypeCompoundInterContractEdge()` — hide `group: type` + `extends` on full graph always
- [x] T021 [US2] Toggle shows function-level `cross_type_*` only, not contract-box links
- [x] T022 [US1] Spec/plan/tests updated; Vitest `hides type-to-type extends even when toggle is on`
