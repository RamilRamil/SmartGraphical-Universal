# Implementation Plan: Inheritance Cross-Type Call Graph

**Spec**: [spec.md](./spec.md)

## Summary

Fix inverted `cross_type_call` edges for inheritance (`child.caller` -> `parent.callee`). Add `import_resolve.py` to expand single-file analysis with relative Solidity siblings. Test with keeper examples.

## Touch points

- `smartgraphical/adapters/solidity/import_resolve.py` (new)
- `smartgraphical/adapters/solidity/adapter.py` — `parse_source`, edge direction
- `tests/unit/test_solidity_inheritance_calls.py` (new)
- `docs/graph_schema_logic.md` — cross_type_call direction note
