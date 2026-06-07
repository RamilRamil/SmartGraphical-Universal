# Tasks: Inheritance Cross-Type Call Graph

**Status**: Complete (2026-05-21)

- [x] T001 [US1] Fix `cross_type_call` direction in `smartgraphical/adapters/solidity/adapter.py` (child caller -> parent callee)
- [x] T002 [US2] Add `smartgraphical/adapters/solidity/import_resolve.py` and wire `parse_source` transitive local `.sol` loading
- [x] T003 [US1/US2] Add `tests/unit/test_solidity_inheritance_calls.py` for `ValidatorChild.sol` / `RewardBase.sol`
- [x] T004 Document `cross_type_call` semantics in `docs/graph_schema_logic.md`
