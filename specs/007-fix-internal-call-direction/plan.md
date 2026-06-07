# Implementation Plan: Fix Solidity Internal Call Edge Direction

**Spec**: [spec.md](./spec.md)

## Summary

Fix inverted `function_to_function` edges in the Solidity adapter: emit caller -> callee when converting `func_func_mapping`. Pass caller body into `_call_metadata_for_target`. Add regression tests; document semantics in `docs/graph_schema_logic.md`.

## Root cause

`extract_func_func_mapping` stores `{callee: [caller, ...]}`. Edge loop treats key as `source` and list entries as `target`, reversing graph arrows.

## Touch points

- `smartgraphical/adapters/solidity/adapter.py` — `function_to_function` edge loop + metadata arguments
- `tests/unit/test_solidity_internal_call_direction.py` (new) — synthetic + optional ImportModifierFixture
- `docs/graph_schema_logic.md` — document caller -> callee for `function_to_function`
- `specs/007-fix-internal-call-direction/tasks.md`

## Out of scope

- Changing `extract_func_func_mapping` index shape (used by legacy rules).
- `cross_type_call` (already correct per spec 002).
