# Implementation Plan: Accurate Solidity State Read/Write Detection

**Branch**: `001-fix-solidity-state-writes` | **Date**: 2026-05-21 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-fix-solidity-state-writes/spec.md`

**Scope**: **Variant B** — accurate `state_writes` / `mutations` **plus** separate read/write graph edges (`state_to_function_read` / `state_to_function_write`).

## Summary

SmartGraphical’s Solidity adapter uses naive substring checks (`name in stmt`, `'=' in stmt`) to detect storage mutations. That produces false writes on `view` functions (e.g. `RewardBase.rewards`) and pollutes rules and graph highlighting. This plan introduces whole-token matching, comparison-safe assignment detection, storage-alias write tracking, a `view`/`pure` write ban, and new graph edge kinds so reviewers can separate readers from writers on the state node panel.

## Technical Context

**Language/Version**: Python 3.x (backend), TypeScript/React (frontend), Solidity ^0.8.x (fixtures)

**Primary Dependencies**: Existing `ContractReader` text pipeline; no new parser libraries

**Storage**: N/A (analysis is in-memory)

**Testing**: `pytest` under `tests/unit/`

**Target Platform**: SmartGraphical API + Cytoscape graph UI

**Project Type**: Analysis library + web frontend

**Performance Goals**: No measurable regression on typical contract files (< few ms per function body)

**Constraints**:

- Heuristic parsing only (no solc AST in v1)
- Minimal diff; reuse `NormalizedStateAccess`, `mutations`, serializer pipeline
- ASCII-only string literals in code

**Scale/Scope**: Solidity adapter + serializer version bump + GraphView panel/legend; C/Rust adapters unchanged

## Constitution Check

*GATE: Constitution template is not yet ratified for this repo; proceed with project norms below.*

| Gate | Status | Notes |
|------|--------|-------|
| Test-first for behavior changes | PASS | Unit + integration tests required before merge (see Phase 3) |
| Minimal scope | PASS | No unrelated refactors |
| Backward compatibility | PASS | Frontend fallback for legacy `state_to_function` edges |
| Documentation | PASS | `docs/graph_schema_logic.md` + contract doc in feature `contracts/` |

**Post-design**: No violations requiring complexity table.

## Project Structure

### Documentation (this feature)

```text
specs/001-fix-solidity-state-writes/
├── plan.md              # This file
├── research.md          # Phase 0
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1 verification
├── contracts/
│   └── graph-state-access-v1.1.md
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks — generated)
```

### Source Code (touch points)

```text
smartgraphical/adapters/solidity/
├── adapter.py           # _collect_mutations, _collect_state_accesses, edge emission
└── state_access.py      # NEW: helpers (token match, write op, aliases, view filter)

smartgraphical/adapters/solidity/reader.py
└── extract_var_func_mapping  # No longer sole source of state edges (keep for legacy rules if needed)

smartgraphical/services/serializers.py
└── _GRAPH_SCHEMA_VERSION = "1.1"

smartgraphical/core/graph.py
└── Render new edge kinds in DOT export (optional parity)

docs/graph_schema_logic.md
└── Document new kinds + migration

frontend/src/
├── api/types.ts         # Edge kind union
└── components/GraphView.tsx  # Readers/Writers panels, legend, edge styles

tests/unit/
├── test_solidity_state_access.py   # NEW
└── test_serializers.py             # Extend edge kind assertions

tests/fixtures/solidity/
└── CollateralStateFixture.sol # NEW minimal patterns
```

**Structure Decision**: Single Python package + frontend consumer; feature-local docs under `specs/001-fix-solidity-state-writes/`.

## Implementation Phases

### Phase A — Core classification (`state_access.py`)

1. **`_whole_token_pattern(name)`** — boundary-safe match.
2. **`_statement_writes_to_var(stmt, name, aliases)`** — denylist `==`, `!=`, `<=`, `>=`, `=>`; allow `+=`, `-=`, plain `=`.
3. **`_statement_reads_var`** — token present, not classified as write.
4. **`_is_local_load_from_storage(stmt, name)`** — RHS read for declaration statements.
5. **`_collect_storage_aliases(body)`** — `storage id = V[...]`.
6. **`_function_is_view_or_pure(ext_params)`** — reuse modifier list from adapter (`view`, `pure` in `_SOLIDITY_MODIFIER_KEYWORDS`).

Refactor `_collect_mutations` and `_collect_state_accesses` in `adapter.py` to call these helpers.

**Acceptance**: Unit tests for each helper + table-driven cases from `RewardBase` snippets.

### Phase B — Function-level aggregation

1. Pass `ext_params` (modifiers) into collectors; if view/pure → return `mutations=[]`, writes=[].
2. Populate `read_accesses` / `mutations` with corrected logic.
3. Derive `state_reads` entity list from read accesses (unchanged serializer contract).

**Acceptance**: Normalized model on fixture — SC-001, SC-002, SC-003.

### Phase C — Graph edges (Variant B)

Replace loop:

```python
for var_name, used_by in var_func_mapping.items():
    ... 'state_to_function'
```

With per-function access sets:

```python
for fn in type_entry.functions:
    for access in fn.read_accesses:
        edge kind state_to_function_read
    for write in write_accesses:
        edge kind state_to_function_write
```

Mirror for `high_connections` → `cross_type_state_read` / `cross_type_state_write`.

**Do not emit** legacy `state_to_function` / `cross_type_state` from Solidity adapter after change.

**Acceptance**: `model_graph_to_dict` edge kinds on fixture; `test_serializers.py` updated.

### Phase D — Schema & docs

1. `_GRAPH_SCHEMA_VERSION = "1.1"`.
2. Update `docs/graph_schema_logic.md` §3 edge kinds table.
3. Keep `contracts/graph-state-access-v1.1.md` in sync.

### Phase E — Frontend

1. `types.ts`: add edge kinds to `GraphEdge.kind`.
2. `GraphView.tsx`:
   - `bucketForEdgeKind`: map read/write state edges to `edge_state` (or sub-buckets).
   - `stateAccessFunctionLabels` → split into `stateReaderLabels` / `stateWriterLabels` using new kinds; fallback legacy `state_to_function` → readers only.
   - Optional: dashed vs solid edge style for write edges.
3. No change to `sg-state-write` class logic (still `state_writes` array).

**Acceptance**: Manual quickstart §3.

### Phase F — Rules regression

Rules already use `function.mutations` — no per-rule edits expected after Phase B.

Run: `test_rules_state_mutation.py`, `test_rules_outer_calls.py`, `test_rules_solidity_normalized_coverage.py`.

## Risk Register

| Risk | Mitigation |
|------|------------|
| Storage alias heuristic misses patterns | Test `harvest`; document limitation in research.md |
| Breaking API consumers of `state_to_function` | Version 1.1 + frontend fallback one release |
| `;` split breaks multiline statements | Keep existing split; add multiline test if needed later |
| False negative on assembly writes | Out of scope per spec |

## Complexity Tracking

*(empty — no constitution violations)*

## Task Generation Preview (for `/speckit-tasks`)

Suggested task order:

1. Add `state_access.py` + unit tests  
2. Wire adapter collectors + view/pure gate  
3. Replace edge emission (intra + cross-type)  
4. Bump schema version + docs  
5. Frontend readers/writers panels  
6. Integration fixture + quickstart validation  

## References

- [research.md](./research.md) — decisions R1–R10  
- [data-model.md](./data-model.md) — entities and pipeline  
- [contracts/graph-state-access-v1.1.md](./contracts/graph-state-access-v1.1.md) — API contract  
- [quickstart.md](./quickstart.md) — verification steps  
- Root cause example: `tests/fixtures/solidity/CollateralStateFixture.sol`
