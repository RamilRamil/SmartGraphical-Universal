# Contract: Intra-compound sandwich layout (client v1)

## Geometry (inside each `type` / `tile` compound)

```text
[modifiers]     top-left column (not in vertical stack)
[public/external functions]   band above state (1-2 sub-rows)
======== state variables (single horizontal line, y=0) ========
[internal/private functions]  band below state (1-2 sub-rows)
[events / custom_error]       column on the right
```

## Constants

| Constant | Value | Role |
|----------|-------|------|
| `MAX_FUNCTIONS_PER_ROW` | 6 | Split band into two sub-rows |
| `ENTRYPOINT_DEGREE_BONUS` | 8 | Pull entrypoints toward state |
| `FUNCTION_BAND_GAP` | 36 | Gap between function band and state line |
| `EVENT_SIDE_GAP` | 48 | Gap before event column |
| `MODIFIER_CORNER_GAP` | 40 | Gap before modifier column |

## Function placement rules

1. `visibility` in `public` | `external` -> band **above** state; else **below**.
2. Row order: sort by **effective degree** desc, then `sortKey` asc.
3. Effective degree = incident interior edge count + `ENTRYPOINT_DEGREE_BONUS` when `is_entrypoint`.
4. If count > `MAX_FUNCTIONS_PER_ROW`: two sub-rows; **near** row (higher degree) closer to state line.

## Layout pass

1. `assignTieredGridSeeds` sets all positions from pure grid (no per-tier fcose).
2. Outer compounds only: `cose-bilkent` / spread seeds (`applyFullGraphTwoPhaseLayout`).

## Inputs

```typescript
type LayoutCell = {
  anchorId: string;
  tier: number;
  sortKey: string;
  visibility?: string;
  isEntrypoint?: boolean;
};

type LayoutEdgeHint = { source: string; target: string };
```

Edge hints: edges whose source and target are both layout anchor ids inside the same compound.
