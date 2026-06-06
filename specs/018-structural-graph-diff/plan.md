# Implementation Plan: Structural graph diff between two scans

**Branch**: `018-structural-graph-diff` | **Date**: 2026-06-06 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/018-structural-graph-diff/spec.md`

## Summary

Add a structural graph diff that compares two scans' stored graph payloads and
reports nodes added/removed/changed (by canonical id) and edges added/removed (by
`(source,target,kind)`), mirroring the existing findings diff. Delivered as a pure
`graph_diff` module (US1 core) + `HistoryService.diff_graphs` (US1 persistence) +
an HTTP endpoint (US2). The web DiffPage visualization (US3) is a separate
frontend increment, specified but not implemented in this slice.

## Technical Context

**Language/Version**: Python 3.10+ backend; (frontend React/TS for US3, deferred).

**Primary Dependencies**: existing `HistoryService` (get_graph, diff guards),
stored graph payload (`web_api.graph` output), FastAPI router. Stdlib only for the
diff core.

**Storage**: reuses per-scan `graph.json` already persisted; no schema change.

**Testing**: pytest — pure-diff unit tests, a HistoryService integration test
(two `run_all` scans), and an HTTP contract test.

**Target Platform**: backend service + HTTP API.

**Project Type**: single backend package; frontend untouched in this slice.

**Performance Goals**: O(n+m) over nodes/edges; no regression.

**Constraints**: MUST NOT change the findings diff, stored graph payload shape,
rule output, or existing endpoints (FR-007). Reuse the same-artifact guard and
not-found error contract as `diff_scans`.

**Scale/Scope**: 1 new pure module + 1 HistoryService method + 1 route + tests.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Pragmatic Parsing Over Full AST** — ✅ Operates on the already-built graph
  payload; no parsing.
- **II. Auditor-Centric** — ✅ Surfaces structural change as hints for the
  reviewer; missing-graph degrades clearly, not hidden.
- **III. Normalized Model Is the Contract** — ✅ Diffs the normalized-model-derived
  canonical graph; no raw-text reparse.
- **IV. Portability** — ✅ Language-agnostic: matches by canonical id/edge triple,
  works for Solidity/C/Rust and bundles identically.
- **V. Two Pillars Stay Connected** — ✅ Brings the graph pillar to parity with the
  findings pillar (which already has diff), keyed on the same canonical entity ids
  feature 017 unified.
- **VI. Stable, Machine-Readable Contracts** — ✅ New endpoint returns JSON-safe
  output; reuses existing error contract; no existing shape changes.
- **VII. Test & Traceability Gates** — ✅ Pure-diff + integration + HTTP tests.
  No new heuristic trade-off → no KNOWN_QUIRKS entry.

**Result**: PASS. No violations; Complexity Tracking empty.

**Post-design re-check**: PASS — no new dependency; additive surface only.

## Project Structure

### Documentation (this feature)

```text
specs/018-structural-graph-diff/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/graph-diff.md
└── checklists/requirements.md
```

### Source Code (repository root)

```text
smartgraphical/services/graph_diff.py             # NEW: pure diff_graph_payloads(...)
smartgraphical/services/history_service.py        # + diff_graphs(scan_a, scan_b)
smartgraphical/interfaces/http/routes.py          # + GET /scans/{id}/graph-diff/{other}
tests/unit/test_graph_diff.py                     # NEW: pure-diff unit tests
tests/unit/test_history_service_graph_diff.py     # NEW: integration (two run_all scans)
tests/integration/test_http_graph_diff.py         # NEW: HTTP contract
# (US3 frontend: DiffPage + client + hook + Vitest — deferred increment)
```

**Structure Decision**: Keep the diff core pure and dependency-free in a new
`services/graph_diff.py` (mirrors `correlateFindings`/benchmark purity), so it is
trivially unit-testable. `HistoryService.diff_graphs` is a thin loader+guard over
it reusing `get_graph` and the `diff_scans` artifact-match/not-found errors. The
route mirrors the existing `diff_scans` route exactly.

## Design detail

### `diff_graph_payloads(payload_a, payload_b) -> dict`
1. Extract `nodes`/`edges` from `payload["model_summary"]["graph"]` on each side;
   tolerate `None`/missing payloads → return an empty diff with
   `graph_available: false`.
2. Node maps keyed by `id`; node "signature" = `(group, label, kind)`.
   - `added_nodes` = ids in B not in A; `removed_nodes` = ids in A not in B;
     `changed_nodes` = same id, different signature (carry `before`/`after`).
3. Edge maps keyed by `(source, target, kind)`.
   - `added_edges` = keys in B not in A; `removed_edges` = keys in A not in B.
4. Return JSON-safe dict with compact node/edge descriptors + `*_count` +
   `unchanged_node_count` + `graph_available: true`.

### `HistoryService.diff_graphs(scan_a_id, scan_b_id)`
- Look up both scans (reuse `_scans.get` + not-found error).
- Same-artifact guard (reuse `ERROR_DIFF_MISMATCH`).
- `get_graph` each; pass to `diff_graph_payloads`; attach `scan_a_id/scan_b_id/
  artifact_id` like `diff_scans`.

### Route
`GET /scans/{scan_id}/graph-diff/{other_id}` → `service.diff_graphs(...)`, placed
next to `diff_scans`.

## Complexity Tracking

> No Constitution violations. Section intentionally empty.
