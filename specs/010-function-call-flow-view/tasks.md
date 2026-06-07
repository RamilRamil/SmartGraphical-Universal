# Tasks: Function Call Flow View

**Status**: Phase 3 implemented (2026-05-24)

## Phase 1 - MVP

- [x] T001 [P] [US1] Add `buildCallFlowSubgraph.ts` + Vitest (limited depth + full expand-all)
- [x] T002 [US1] Add `CallFlowModal.tsx` (Cytoscape; breadthfirst/cose layout, no dagre)
- [x] T003 [US1] Wire **Call flow** button in `GraphView.tsx` (function only)
- [x] T004 [US2] Toolbar: direction, depth 1-4, default both/2
- [x] T005 [US5] **Expand full chain** button (depthMode=full, both directions, cap 150)
- [x] T006 [US3] Include `cross_contract_call` by default; toggle to hide
- [x] T007 [US4] Empty states + truncation banner
- [x] T008 [US1] Styles (`.sg-call-flow-*`); quickstart manual steps pending user verify

## Phase 2

- [x] T009 Non-function call targets (stub external/type node)
- [x] T010 Modal node click syncs selection on main graph after close

## Phase 3 (optional)

- [x] T011 Export PNG (modal toolbar, Cytoscape png full canvas)
- [x] T012 sessionStorage for direction/depth/depthMode/showExternalCalls

## Dependencies

- T001 before T002-T007
- Spec 007 call direction in test scans
