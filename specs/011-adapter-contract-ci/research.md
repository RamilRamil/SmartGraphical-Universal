# Phase 0 Research: Adapter Contract, C/Rust Web Analysis, CI

All unknowns from the Technical Context are resolved below. No `NEEDS
CLARIFICATION` remained after reading the code.

## D1. What is the adapter contract's return type?

**Decision**: The contract entry point is
`parse_source(source_path: str, *, expand_local_imports: bool = True) ->
AnalysisContext`. The return is `AnalysisContext` (from
`smartgraphical/core/model.py`), which carries `.normalized_model`
(a `NormalizedAuditModel`).

**Rationale**: All three adapters already return `AnalysisContext`
(`solidity/adapter.py:873`, `c_base/adapter.py:822`, `rust_stellar/adapter.py:627`),
and the service consumes the context (`run_task(context, ...)`,
`render_graph(context)` reads `context.path` and `context.normalized_model`). The
spec phrase "return value of the normalized audit model type" is satisfied by the
context that wraps it; changing the return to a bare model would break the service
and rule engine. So the contract standardizes on `AnalysisContext`.

**Alternatives considered**: Return `NormalizedAuditModel` directly — rejected,
it would force a wider refactor of the service/engine and violate FR-005
backward compatibility.

## D2. How to make `expand_local_imports` uniform across adapters?

**Decision**: Add `*, expand_local_imports: bool = True` to the keyword-only
signature of the C and Rust `parse_source`. C and Rust **accept and ignore** it
(documented no-op) until they implement their own local-import expansion.

**Rationale**: FR-004 requires the option be accepted uniformly. Aligning the
signature (rather than making the caller branch per language) keeps the facade
and `AnalysisService.analyze(**parse_kwargs)` language-agnostic and satisfies
Principle III (one contract). It is the smallest change that closes the whole
class of bug.

**Alternatives considered**:
- Make `web_api`/`AnalysisService` strip `expand_local_imports` for non-Solidity
  adapters — rejected: pushes language knowledge back into the facade, the exact
  coupling the contract is meant to remove; conformance could not be asserted by
  signature.
- Use `**kwargs` catch-all on every adapter — rejected: hides typos and defeats
  the conformance guarantee; an explicit keyword is self-documenting.

## D3. Protocol vs ABC for the contract?

**Decision**: Use `typing.Protocol` (structural) as the declared contract type,
plus a runtime conformance **test** (not inheritance) that verifies each
registered adapter via `inspect.signature`.

**Rationale**: Adapters are independently constructed (`SolidityAdapterV0()`,
`CBaseAdapterV0()`, `RustStellarAdapterV0()`); a Protocol documents the shape
without forcing a base-class import cycle (the Protocol references
`core.model.AnalysisContext`). The teeth come from the conformance test
(Principle VII), which fails on signature drift and names the offender (FR-003).

**Alternatives considered**: `abc.ABC` base class — viable but adds inheritance
coupling and a shared import; the structural Protocol + test gives the same
guarantee with less coupling. Recorded as the rejected alternative; either is
constitution-compliant.

## D4. Triage of the 3 non-facade failures (needed for SC-002 "zero failures")

Confirmed by running each with tracebacks. None are environmental; none share the
`expand_local_imports` cause.

| Test | Cause | Fix |
|------|-------|-----|
| `test_solidity_adapter_fixtures.py::test_minimal_guard_phase5_shape_snapshot` | Stale golden: adapter now correctly emits `state_entities:["amount"]` (spec 008 state-var-types), golden still expects `[]`. | Update the golden snapshot to include `amount`; confirm `amount` is a legitimate state entity of `MinimalGuard`. Behavior is an improvement, not a regression. |
| `test_c_adapter_model_graph.py::test_minimal_include_tu_discovers_inc_workspace_node` | Graph regression: include-template edge source `__tu_include_anchor__` resolves to `external:unresolved_symbol:__tu_include_anchor__` instead of `tile:MinimalIncludeTu`. | Fix anchor resolution in `serializers.py` (see D5). |
| `test_c_adapter_model_graph.py::test_c_graph_include_template_edges` | Same regression: function node's `calls_include_template` is `False` because the anchored edge did not resolve to the TU tile. | Same fix as above. |

## D5. Root cause of the C include-template anchor regression

`model_graph_to_dict.resolve_endpoint` has a special case
(`serializers.py:676-683`) for `target_name == _TU_INCLUDE_EDGE_SOURCE`
(`"__tu_include_anchor__"`) that returns `_type_id(type_name)`. But
`_type_id` returns `f"type:{type_name}"` (`serializers.py:177`), while the C
translation-unit node is created as `f"tile:{label}"` (`serializers.py:269`).
The `type:`-prefixed id is never in `node_ids` for a C TU, so the special case
falls through and the anchor becomes a synthetic `external:unresolved_symbol:*`
node (Quirk 5 fallback).

**Decision**: In the anchor special case, resolve to the C TU **tile** id
(`tile:<label>`), e.g. try the tile id before / instead of `_type_id`, so the
include-template edge originates from the TU tile and `calls_include_template`
becomes `True`.

**Rationale**: This is a one-spot identity fix that restores Principle V (graph
node identity matches the model's TU) without touching the C adapter's edge
emission. It is independent of the adapter-contract change, so it can land as its
own task.

**Quirk note**: If the `tile:` vs `type:` duality is intentional (Solidity uses
`type:`, C uses `tile:`), record the anchor-resolution rule in `KNOWN_QUIRKS.md`
per Principle VII.

## D6. CI provider and matrix

**Decision**: GitHub Actions, `ubuntu-latest`, Python `3.12` primary with `3.10`
floor in the matrix; steps: install `requirements.txt`, run `pytest`, run a
`sg_cli.py ... --format json` smoke on a known fixture and assert valid JSON.
Trigger on `push` and `pull_request`.

**Rationale**: The repo targets GitHub remotes (Spec Kit git extension); the
Dockerfile already standardizes on `python:3.12-slim`, and the constitution sets
3.10 as the floor — testing both guards the `X | None` syntax boundary.

**Alternatives considered**: single Python version — rejected, it would not catch
3.10/3.12 drift; other CI providers — rejected, GitHub is the established remote.
