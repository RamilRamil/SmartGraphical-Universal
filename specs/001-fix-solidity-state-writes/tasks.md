# Tasks: Accurate Solidity State Read/Write Detection

**Input**: Design documents from `/specs/001-fix-solidity-state-writes/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/graph-state-access-v1.1.md

**Tests**: Included per spec FR-008 / SC-004 (regression fixtures and unit coverage).

**Organization**: Tasks grouped by user story (Variant B: accurate writes + read/write graph edges).

**Status**: Implementation complete (2026-05-21).

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks in same phase)
- **[Story]**: US1, US2, US3 from spec.md

## Path Conventions

- Backend: `smartgraphical/` at repository root
- Frontend: `frontend/src/`
- Tests: `tests/unit/`, fixtures in `tests/fixtures/solidity/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Fixtures and module scaffold before classification logic

- [x] T001 Create minimal Solidity fixture `tests/fixtures/solidity/CollateralStateFixture.sol` with view read patterns, `rewardsNonce` prefix collision, and write paths (`harvest`-style storage alias, `_collateralize`-style direct assign)
- [x] T002 [P] Create module scaffold `smartgraphical/adapters/solidity/state_access.py` with documented public helpers (token match, write detection, aliases, view/pure gate) stubbed for import from `adapter.py`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core classification library and unit tests — **blocks all user stories**

- [x] T003 Implement whole-token matching and comparison-safe write-operator detection in `smartgraphical/adapters/solidity/state_access.py` (exclude `==`, `!=`, `<=`, `>=`, `=>`; allow `=`, `+=`, `-=`)
- [x] T004 Implement local storage load vs write, `storage` alias binding map, and `collect_function_state_accesses(body, state_names, modifiers)` returning reads/writes in `smartgraphical/adapters/solidity/state_access.py`
- [x] T005 Add `tests/unit/test_solidity_state_access.py` with table-driven cases from `specs/001-fix-solidity-state-writes/research.md` and `RewardBase` snippets (token boundary, `!=`, local load, alias field write, view/pure empty writes)

---

## Phase 3: User Story 1 - Trustworthy write highlighting (Priority: P1) 🎯 MVP

- [x] T006 [US1] Refactor `_collect_mutations` and `_collect_state_accesses` in `smartgraphical/adapters/solidity/adapter.py` to delegate to `state_access.collect_function_state_accesses`
- [x] T007 [US1] Pass function modifiers into collectors in `build_normalized_model` in `smartgraphical/adapters/solidity/adapter.py`; enforce zero write `mutations` for `view`/`pure`
- [x] T008 [US1] Add normalized-model integration tests in `tests/unit/test_solidity_state_access.py` asserting `NormalizedFunction.mutations` and graph-bound `state_writes` entity names for `rewards` on the fixture (positive and negative cases per quickstart.md)

---

## Phase 4: User Story 2 - Distinct read vs write linkage (Priority: P2)

- [x] T009 [US2] Replace `var_func_mapping` `state_to_function` emission with per-function `state_to_function_read` / `state_to_function_write` from `read_accesses` and write accesses in `smartgraphical/adapters/solidity/adapter.py`
- [x] T010 [US2] Emit `cross_type_state_read` / `cross_type_state_write` for `high_connections` in `smartgraphical/adapters/solidity/adapter.py`
- [x] T011 [US2] Set `_GRAPH_SCHEMA_VERSION = "1.1"` in `smartgraphical/services/serializers.py` and ensure new edge kinds pass through serialization unchanged
- [x] T012 [P] [US2] Extend `tests/unit/test_serializers.py` for new edge kinds
- [x] T013 [P] [US2] Edge kinds consumed in `frontend/src/components/GraphView.tsx` (types remain `string` on `GraphEdge.kind`)
- [x] T014 [US2] Split Readers/Writers panels and legend in `frontend/src/components/GraphView.tsx`
- [x] T015 [P] [US2] Update `smartgraphical/core/graph.py` DOT export for new edge kinds

---

## Phase 5: User Story 3 - Reliable rule findings (Priority: P2)

- [x] T016 [US3] Add rule regression case in `tests/unit/test_solidity_state_access.py` — expect no unallowed-manipulation alert for view reader of `rewards`
- [x] T017 [P] [US3] Existing rule unit tests pass (`test_rules_state_mutation`, `test_rules_outer_calls`)

---

## Phase 6: Polish & Cross-Cutting Concerns

- [x] T018 Update `docs/graph_schema_logic.md` section 3 (Solidity edge kinds) with v1.1 read/write kinds
- [x] T019 Validate via `python3 -m unittest tests.unit.test_solidity_state_access` (quickstart subset)
