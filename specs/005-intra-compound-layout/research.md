# Research: Intra-Contract Graph Layout

## Current behavior (diagnosis)

| Factor | Effect |
|--------|--------|
| Single global `cose-bilkent` on all nodes | Cross-contract edges pull inner nodes away from their compound cluster. |
| Full graph preset: `idealEdgeLength: 80`, `nodeRepulsion: 5000`, `randomize: true` | Non-reproducible; weak compound separation (no `nestingFactor` / `gravityCompound`). |
| `modifier_ring` compound nesting | Each applied modifier adds a padded compound wrapper around a function, inflating bbox. |
| Fixed 36x36 node size + `nodeDimensionsIncludeLabels: true` | Long identifiers widen nodes; force layout fights label width. |
| State read/write edges inside contract | Many short edges create dense force graph inside compound. |

Relevant code: `frontend/src/components/GraphView.tsx` (layout options ~L843-863, styles ~L869-999).

`cytoscape-fcose` is listed in `package.json` but **not registered** in GraphView today.

## Option A - Tune cose-bilkent only

Add `nestingFactor`, `gravityCompound`, `gravityRangeCompound`, lower `randomize`, higher repulsion.

| Pros | Cons |
|------|------|
| Minimal diff | Does not fix outlier pull from external edges |
| | Overlap may persist on dense contracts |

**Verdict**: Insufficient alone.

## Option B - Switch to fcose (whole graph)

Register `cytoscape-fcose` with compound-aware defaults.

| Pros | Cons |
|------|------|
| Better compound support than plain cose-bilkent | Still one global pass; cross-compound edges affect inner nodes |
| Already a dependency | Hard to unit test |

**Verdict**: Good outer layout; pair with inner preset (Option C).

## Option C - Two-phase: tiered grid inside, force outside (recommended)

1. **Phase 1 (deterministic)**: For each compound root, assign grid positions to layout cells grouped by kind tier (states/modifiers, then functions with ring trees, then events/errors).
2. **Phase 2 (force)**: Run `fcose` or `cose-bilkent` on `:parentless` nodes only; children stay fixed.

| Pros | Cons |
|------|------|
| Eliminates overlap by construction | Requires new module + tests |
| Cuts outlier problem (external edges ignored in phase 1) | Grid may look less "organic" |
| Reproducible (`randomize: false`) | Tuning constants per tier |

**Verdict**: **Selected** for FR-001..FR-003.

## Option D - Flatten modifier_ring compounds

Replace ring compounds with function border styling only.

| Pros | Cons |
|------|------|
| Smaller compound bbox | UI behavior change; larger diff |
| | Out of v1 scope per spec assumptions |

**Verdict**: Future optimization if SC-002 not met after Option C.

## Decision summary

- **Decision**: Implement Option C in `frontend/src/graph/intraCompoundLayout.ts`; use **fcose** for outer pass (Option B) with `randomize: false`.
- **Rationale**: Directly addresses overlap, outliers, and tile area; testable pure functions.
- **Alternatives considered**: A (too weak), B alone (still couples inner/outer), D (deferred).
