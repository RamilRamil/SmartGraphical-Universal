# Implementation Plan: Intra-Contract Graph Layout

**Branch**: `005-intra-compound-layout` | **Date**: 2026-05-24 | **Spec**: [spec.md](./spec.md)

## Summary

Replace single-pass force layout on full graph with **two-phase layout**: deterministic tiered grid inside each `type`/`tile` compound, then **fcose** on top-level compounds only. Inter-contract overview keeps existing cose-bilkent path.

## Technical Context

**Language**: TypeScript (React + Cytoscape)

**Dependencies**: `cytoscape`, `cytoscape-fcose` (already installed), `cytoscape-cose-bilkent` (overview only)

**Testing**: Vitest in `frontend/src/graph/intraCompoundLayout.test.ts`

**Constraints**: View-layer only; no graph schema version bump; ASCII literals in code comments/strings.

## Touch points

| File | Change |
|------|--------|
| `frontend/src/graph/intraCompoundLayout.ts` | **New** — tier types, grid cell builder, overlap metrics, `applyIntraCompoundLayout(cy)` |
| `frontend/src/graph/intraCompoundLayout.test.ts` | **New** — cell grouping, zero overlap, outlier checks on fixture nodes |
| `frontend/src/components/GraphView.tsx` | Register fcose; two-phase layout for full graph; keep overview layout branch |

## Layout algorithm (full graph)

### Phase 1 — intra-compound grid

For each compound root (`group` in `type`, `tile`):

1. Collect **layout cells**: each direct child of root, expanding `modifier_ring` chains to one cell per function tree.
2. Assign cells to tiers (top to bottom relative Y):
   - Tier 0: `state`, `workspace`
   - Tier 1: `modifier`
   - Tier 2: `function` trees (via outermost `modifier_ring` or bare function)
   - Tier 3: `event`, `custom_error`
3. Within tier, place cells on a row-major grid with constants:
   - `CELL_W = 72`, `CELL_H = 56`, `TIER_GAP = 24`, `COL_GAP = 16`
4. Set relative positions on cell anchor nodes (outermost node in each tree).

### Phase 2 — outer fcose

```text
cy.nodes(':parentless').layout({
  name: 'fcose',
  randomize: false,
  animate: false,
  nodeDimensionsIncludeLabels: true,
  idealEdgeLength: 120,
  nodeRepulsion: 8000,
  nestingFactor: 0.9,
  gravityCompound: 1.2,
  tile: true,
})
```

Children positions locked (no layout call on compounds' descendants).

## Constitution Check

- Minimal diff: one new module + GraphView wiring.
- No new npm packages.
- Overview mode untouched.

## Project Structure

```text
specs/005-intra-compound-layout/
├── spec.md
├── plan.md
├── research.md
├── tasks.md
└── checklists/requirements.md
```
