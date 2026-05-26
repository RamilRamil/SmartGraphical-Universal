# Research: Fix Solidity Internal Call Edge Direction

## Decision

Emit `function_to_function` edges as **caller -> callee** by swapping roles when converting `func_func_mapping` to `NormalizedCallEdge`.

## Rationale

- `ContractReader.extract_func_func_mapping` indexes **callee -> [callers]** (see nested loops: outer `i` is callee token, inner `j` is caller body index).
- `adapter.py` currently uses mapping key as `source_name` and value as `target_name`, producing **callee -> caller** on the graph.
- Spec 002 already fixed `cross_type_call` by explicitly mapping `child caller -> parent callee`.
- C adapter `_build_c_call_edges` already emits caller -> callee.
- `min_slippage_bounds` and `_derive_write_paths` assume `source` = caller, `target` = callee.

## Alternatives considered

1. **Change reader mapping to caller -> callees**: Would break `outer_calls`, `intra_contract_connection`, and rules reading raw `func_func_mapping`.
2. **Reverse only in frontend**: Would leave rules/serializer/write_paths wrong; rejected.

## Metadata fix

`_call_metadata_for_target` must receive **caller body** and **callee name** (including `super.` prefix when applicable). The pre-fix code passed callee as body key and caller as callee name, so args_map was wrong for reversed edges.
