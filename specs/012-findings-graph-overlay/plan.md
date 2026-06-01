# Implementation Plan: Findings Overlay on the Interactive Graph

**Branch**: `012-findings-graph-overlay` | **Date**: 2026-06-01 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/012-findings-graph-overlay/spec.md`

## Summary

Connect the two pillars in the web UI: mark graph nodes that own findings (count +
confidence color), let an auditor jump from a finding to its node, filter the
graph to the finding-owning surface, and list a node's findings on selection.

Decisive architectural finding (confirmed by reading the code): `ScanDetailPage`
already holds **both** datasets at once — `useScan` returns `findings[]` and
`useGraph` returns the graph payload. And the correlation key needs no node-id
reconstruction: a finding's evidence carries `type_name` + `function_name`, and
each `GraphNode` already carries `type_name` and `label`. So correlation is a
**pure frontend** operation over data already present, with **zero backend
payload change** (best possible outcome for constitution Principle VI). It also
fits the established `frontend/src/graph/*.ts` + Vitest pattern (e.g.
`focusNeighborhood.ts`).

## Technical Context

**Language/Version**: TypeScript (React 18 + Vite). No backend/Python change.

**Primary Dependencies**: existing — `cytoscape` (+ cose-bilkent/fcose), TanStack
Query, React Router. **No new dependency.**

**Storage**: N/A — no persistence/schema/API change.

**Testing**: Vitest (`npm run test` → `vitest run`), matching the existing
`src/graph/*.test.ts` modules. Playwright exists for e2e but is not required here.

**Target Platform**: the local web UI (browser).

**Project Type**: Web frontend feature (single package `frontend/`).

**Performance Goals**: correlation + overlay render feel instant for graphs up to
~500 function nodes (consistent with feature 010's target); correlation is
O(findings + nodes) using a lookup index.

**Constraints**: backend graph payload and findings list contracts unchanged
(additive-or-nothing); confidence shown honestly (low visibly muted); correlation
works for Solidity, C, Rust/Stellar via shared semantic fields, no per-language
branching in UX.

**Scale/Scope**: 1 new pure module + tests; targeted changes to `GraphView`,
`ScanDetailPage`, and the finding card affordance. Graph remains task `all`-only.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after design.*

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing Over Full AST | PASS — no parsing change; pure UI correlation. |
| II. Auditor-Centric, Human-in-the-Loop | DIRECTLY SERVES — node styling encodes confidence honestly; low-only nodes are visibly muted; unmapped findings surfaced, never dropped. |
| III. Normalized Model Is the Contract | PASS — no adapter/model change; correlation reads existing normalized-derived fields. |
| IV. Portability Across Languages | DIRECTLY SERVES — match on `type_name`/`label` (present for all languages); no per-language special-casing. |
| V. Two Pillars Stay Connected | THE FEATURE — findings and graph reference the same entities; bidirectional navigation. |
| VI. Stable, Machine-Readable Contracts | PASS (strongest form) — zero backend payload change; correlation is pure frontend over existing data. |
| VII. Test & Traceability Gates | PASS — pure correlation module covered by Vitest across Solidity/C/Rust-shaped fixtures. |

**Result**: No violations. Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/012-findings-graph-overlay/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 decisions
├── data-model.md        # correlation entities + matching rules
├── contracts/
│   ├── correlation-module.md   # pure module function contract
│   └── graphview-props.md      # additive GraphView prop contract
├── quickstart.md
└── checklists/requirements.md  # all passed
```

### Source Code (repository root = `SmartGraphical/`)

```text
frontend/src/
├── graph/
│   ├── correlateFindings.ts         # NEW: findings[] + GraphNode[] -> per-node summary + finding->node map + unmapped
│   └── correlateFindings.test.ts    # NEW: Vitest (Solidity/C/Rust-shaped cases, mixed confidence, unmapped)
├── components/
│   ├── GraphView.tsx                # CHANGE: additive props (findingSummaries, focusNodeId, only-findings filter); badge/border styling; node-findings in side panel (US4)
│   └── FindingCard.tsx              # CHANGE: optional "Show on graph" affordance (callback)
└── pages/
    └── ScanDetailPage.tsx           # CHANGE: compute correlation (findings + graphData both present), wire finding->graph navigation (setTab + focusNodeId), pass summaries, handle unmapped
```

**No backend files change.** (If a future need arises to persist correlation, it
would be an additive serializer field — explicitly out of scope here.)

**Structure Decision**: pure-module-first. All correlation logic lives in
`correlateFindings.ts` (testable in isolation); components consume its output.

## Phase Overview

- **Phase 0 (research.md)**: confirm frontend-vs-backend decision, the no-id-
  reconstruction matching rule, confidence ordering, multi-match handling, reuse
  of the focus/filter patterns.
- **Phase 1 (data-model.md + contracts/ + quickstart.md)**: define the
  correlation function contract, the additive GraphView prop contract, the node
  summary shape, and validation steps; update agent context.
- **Phase 2 (/speckit.tasks)**: tasks per user story (US1 styling, US2 navigate,
  US3 filter, US4 node panel), pure module + tests first.

## Complexity Tracking

No constitution violations — no entries.
