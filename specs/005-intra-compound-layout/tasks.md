# Tasks: Intra-Contract Graph Layout

**Status**: Sandwich layout phases 1-3 complete (2026-05-24)

## Phase 1 - State line + modifier corner

- [x] T001 State variables in one horizontal row
- [x] T002 Modifiers in top-left corner (excluded from vertical stack)
- [x] T003 Skip fcose on modifier tier

## Phase 2 - Function sandwich + events side

- [x] T004 Public/external functions above state; internal/private below
- [x] T005 Events and custom_error in right-hand column
- [x] T006 Split function bands at 6 cells; high degree nearer state
- [x] T007 Interior edge hints for degree from compound cy
- [x] T008 Skip fcose on function and event tiers

## Phase 3 - Polish (deterministic inner layout)

- [x] T009 Remove all per-tier fcose inside compounds (grid-only seeds)
- [x] T010 `ENTRYPOINT_DEGREE_BONUS` + `is_entrypoint` on layout cells
- [x] T011 Spec-kit: contract `intra-compound-sandwich-layout-v1.md`, plan/spec/research updates

## Original MVP (pre-sandwich)

- [x] T100 Add `intraCompoundLayout.ts` + wire `GraphView.tsx`
- [x] T101 Inter-contract overview unchanged
- [x] T102 Vitest overlap / tier tests
