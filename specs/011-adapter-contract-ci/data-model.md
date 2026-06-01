# Phase 1 Data Model: Adapter Contract

This feature is infrastructure; the "entities" are the contract types and the
conformance relationship, not persisted data.

## Entity: AnalysisAdapter (the contract)

The single interface every language adapter implements. Declared as a
`typing.Protocol` in `smartgraphical/adapters/base.py`.

| Member | Signature | Notes |
|--------|-----------|-------|
| `parse_source` | `(self, source_path: str, *, expand_local_imports: bool = True) -> AnalysisContext` | The only required method. Keyword-only flag, default `True`. |

Return contract: a populated `AnalysisContext` (see below) whose
`normalized_model` is a `NormalizedAuditModel`.

Behavioral contract:
- MUST return an `AnalysisContext` with `path`, `language`, `lines`,
  `unified_code`, and a non-null `normalized_model`.
- MUST accept `expand_local_imports`. If the adapter does not implement
  local-import expansion (C, Rust today), it MUST treat the flag as a no-op and
  MUST NOT raise.
- MUST NOT require any positional argument beyond `source_path`.

## Entity: AnalysisContext (existing, unchanged)

From `smartgraphical/core/model.py`. The carrier returned by every adapter; this
feature does not change its fields. Relevant fields for the contract:

| Field | Used by |
|-------|---------|
| `path` | `render_graph`, reports |
| `language` | facade reports, serializers |
| `lines`, `unified_code` | exploration, evidence line inference |
| `normalized_model` | rule engine, graph serializer (the two pillars) |

## Entity: Language Adapter (the implementors)

| Adapter | Module | Change in this feature |
|---------|--------|------------------------|
| `SolidityAdapterV0` | `adapters/solidity/adapter.py` | none — it is the reference signature |
| `CBaseAdapterV0` | `adapters/c_base/adapter.py` | add `*, expand_local_imports=True` no-op |
| `RustStellarAdapterV0` | `adapters/rust_stellar/adapter.py` | add `*, expand_local_imports=True` no-op |

## Relationship: Conformance Check

`tests/unit/test_adapter_contract_conformance.py` asserts, for every registered
adapter instance (the same ones the facade/CLI build per language):

1. `parse_source` exists and is callable.
2. Its signature accepts a keyword `expand_local_imports` (via
   `inspect.signature`) and requires no positional parameter other than
   `source_path`.
3. Calling `parse_source(fixture, expand_local_imports=True)` and
   `parse_source(fixture, expand_local_imports=False)` both return an
   `AnalysisContext` with a non-null `normalized_model` (smoke per language using
   existing fixtures under `tests/fixtures/`).

Failure mode (FR-003): the test fails and names the offending adapter class.

## Graph identity rule (C include-template)

Not a new entity — a correctness rule the serializer must honor:

- The C translation-unit node id is `tile:<label>`.
- An include-template edge whose source sentinel is `__tu_include_anchor__` MUST
  resolve its source endpoint to that `tile:<label>` node (not to a `type:`-style
  id and not to a synthetic `external:*` node), so the TU function nodes carry
  `calls_include_template = True`.
