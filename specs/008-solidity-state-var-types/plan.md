# Implementation Plan: Solidity State Variable Type Coverage

**Spec**: [spec.md](./spec.md)

## Summary

Extend `ContractReader.extract_variables` type matching for sized integers/bool/bytes and user-defined storage types. Add unit tests; document in `docs/graph_schema_logic.md`.

## Touch points

- `smartgraphical/adapters/solidity/reader.py` — `extract_variables`, optional `_storage_type_patterns`
- `tests/unit/test_solidity_state_variables.py` (new)
- `docs/graph_schema_logic.md` — state extraction note
