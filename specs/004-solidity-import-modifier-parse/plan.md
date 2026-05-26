# Implementation Plan: Solidity Import Graph and Override Modifier Parsing

**Branch**: `004-solidity-import-modifier-parse` | **Date**: 2026-05-24 | **Spec**: [spec.md](./spec.md)

## Summary

Two root causes in EthMetaVault single-file graph:

1. **Phantom EthMetaVault**: `_append_import_usage_edges` emits unused imports with `source_name=contract_name`. `resolve_endpoint` fails to find `function:EthMetaVault.EthMetaVault` and creates `external:EthMetaVault`.
2. **Split override tokens**: `extract_fparams` splits signature tail on spaces, breaking `override(A, B)` into multiple modifier tokens; serializer treats visibility keywords as modifier nodes.

## Technical Context

**Language**: Python 3 (Solidity adapter + serializers)

**Testing**: `tests/unit/test_solidity_helpers.py`, new `tests/unit/test_solidity_import_modifier_graph.py`

## Touch points

| File | Change |
|------|--------|
| `smartgraphical/adapters/solidity/reader.py` | Parenthesis-aware `_split_ext_params`; use in `extract_fparams` |
| `smartgraphical/services/serializers.py` | Contract-level import source resolution; filter signature tokens from modifier graph |
| `tests/unit/test_solidity_helpers.py` | Override/reinitializer fparams tests |
| `tests/unit/test_solidity_import_modifier_graph.py` | EthMetaVault graph regression |

## Constitution Check

- Minimal diff; no schema version bump.
- ASCII string literals only.
