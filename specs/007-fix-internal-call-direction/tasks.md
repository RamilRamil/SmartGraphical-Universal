# Tasks: Fix Solidity Internal Call Edge Direction

**Status**: Complete (2026-05-24)

- [x] T001 [US1] Fix `function_to_function` emission in `smartgraphical/adapters/solidity/adapter.py` (caller -> callee; caller body for metadata)
- [x] T002 [US1] Add `tests/unit/test_solidity_internal_call_direction.py` (synthetic contract + optional ImportModifierFixture)
- [x] T003 [US2] Document `function_to_function` direction in `docs/graph_schema_logic.md`
- [x] T004 [US1] Run `python -m unittest tests.unit.test_solidity_internal_call_direction tests.unit.test_solidity_inheritance_calls -v`
