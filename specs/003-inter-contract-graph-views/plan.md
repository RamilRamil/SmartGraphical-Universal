# Implementation Plan: Inter-Contract Graph Views

**Branch**: `003-inter-contract-graph-views` | **Date**: 2026-05-21 | **Spec**: [spec.md](./spec.md)

## Summary

Split graph edge visibility by view mode: **full** graph shows intra-contract structure only (+ optional external calls); **inter-contract** overview shows collapsed contract-to-contract semantics and suppresses redundant file-level `bundle_import` when a `cross_type_*` edge already links the same pair.

## Technical Context

**Language/Version**: TypeScript (React + Cytoscape), existing SmartGraphical frontend

**Primary Dependencies**: `cytoscape`, `cytoscape-cose-bilkent`, Vitest

**Testing**: `frontend/src/graph/interContractOverview.test.ts`

**Target Platform**: Web UI (`frontend/src/components/GraphView.tsx`)

**Constraints**: View-layer only; do not change `web_api.py` bundle edge attachment

## Touch points

| File | Change |
|------|--------|
| `frontend/src/graph/interContractOverview.ts` | Export `INTER_CONTRACT_EDGE_KINDS`, `FULL_GRAPH_EXTERNAL_EDGE_KINDS`; `filterFullGraphEdges()`; dedupe `bundle_import`/`tile_to_tile` in `toInterContractOverviewGraph()` |
| `frontend/src/components/GraphView.tsx` | `displayGraph` useMemo wires filter + overview; `applyGraphVisibility` split by mode; toolbar labels/disabled state; tap/highlight visible-only; clear `selectedEdge` on mode switch |
| `frontend/src/graph/interContractOverview.test.ts` | Dedupe + import-only regression tests |

## View matrix

| Edge kind | Full graph (default) | Full + cross-contract toggle | Inter-contract |
|-----------|----------------------|------------------------------|----------------|
| `function_to_function`, state read/write | visible | visible | collapsed/hidden (intra-compound dropped) |
| `cross_type_*` type-to-type (`extends`) | **always hidden** | **always hidden** | visible |
| `cross_type_*` function-level | hidden | visible (toggle) | visible (collapsed) |
| `cross_contract_call`, `function_to_object` | hidden | visible | visible (if cross-compound) |
| `bundle_import`, `tile_to_tile` | visible | hidden if semantic dedupe | hidden if semantic dedupe |

**Toggle UX**: `structureGraph` holds full edges on full graph; toggle only runs `applyGraphVisibility` (no Cytoscape rebuild).

## Constitution Check

- Minimal diff: no new npm packages; no backend schema version bump.
- ASCII string literals in UI copy.

## Project Structure

```text
specs/003-inter-contract-graph-views/
├── spec.md
├── plan.md
├── tasks.md
└── quickstart.md
```
