# Phase 0 Research: Intra-Procedural Taint

## D0. Discovery: the `requires_dataflow` rules already execute

**Finding**: `c_base/adapter.py` registers C tasks (RuleSpecs) including the
`requires_dataflow` rules (e.g. task 15 `unsupported_program_id_divergence`),
and those runners read `findings_data.function_facts[*].dataflow` (built by
`_extract_dataflow_facts`: `program_guard_sites`, `return_error_codes`,
`io_uring_submit_sites`, `tile_markers`). They are invoked by the rule engine —
the docs' "registered but not executed" is stale; they run on bespoke,
rule-specific facts.

**Consequence (scope honesty)**: the new value is a **generic, portable**
source->sink taint + a portable rule (US1/US2). US3 is reframed to: a test
proving the 5 `requires_dataflow` rules are invoked (SC-002), and that the new
`taint_paths` facts are additive (no regression). We do not claim to un-skip
rules that already run.

## D1. Where to compute taint (portable, one seam)

**Decision**: a **core, language-agnostic** module
`smartgraphical/core/dataflow/taint.py` with `compute_taint(function) -> list`
and `apply_taint(model)`, called once in `AnalysisService.analyze` after
`adapter.parse_source(...)`. Results attach to a new additive
`NormalizedFunction.taint_paths` field.

**Rationale**: `AnalysisService.analyze` is the single seam shared by every
language (and the CLI/web facade reuse it), so one call gives C and Solidity
taint uniformly (Principle IV). A new `NormalizedFunction` field is additive and
language-neutral, unlike the C-only `function_facts.dataflow` slot.

**Alternatives considered**: per-adapter computation (duplicated, drift risk);
storing in `function_facts.dataflow` (C-only structure, not portable);
lazy per-rule computation (recomputed N times, non-deterministic ordering risk).

## D2. Taint sources and sinks (heuristic vocabulary)

**Decision**:
- **Sources** (initially tainted): `function.inputs` (parameter names); plus
  statements matching untrusted-read patterns (`recv`, `read`, `recvfrom`,
  `packet`, `deserialize`, `decode`, `parse`, `msg.data`, `calldata`) whose
  assigned LHS becomes tainted.
- **Sinks** (sensitive): `function.mutations` (state writes); plus statements
  matching sink patterns (state assignment, `transfer`, `send`, `write`,
  `store`, `memcpy`, critical-call tokens).

**Rationale**: reuses the existing fact vocabulary (inputs, mutations) plus a
small, tunable token set; no AST. Tokens are documented and adjustable.

## D3. Propagation + guard heuristic

**Decision**: walk `function.exploration_statements` (fall back to splitting
`function.body` on `;`/newlines) in order. Maintain a `tainted` set seeded with
input params. For each statement:
- if it is an assignment `lhs = rhs` and `rhs` references a tainted name or an
  untrusted-read source, add `lhs` to `tainted`;
- if it is a sink statement referencing a tainted name, record a `TaintPath`
  (source name, sink statement, source/sink indices, `guarded`).
`guarded` is True if a guard (`function.guard_facts`, or a `require`/`if`/assert
statement that references the tainted name) appears at or before the sink. A
re-assignment of a tainted var to a constant clears its taint (best-effort).

**Rationale**: linear, deterministic, intra-procedural; captures the common
"input used in a write without a check" pattern. Aliasing/indirection is a known
false negative (documented).

## D4. The additive `taint_paths` field

**Decision**: add `taint_paths: list = []` to `NormalizedFunction`. Each entry:
`{ "source", "sink", "source_index", "sink_index", "guarded" }`. Existing
`function_facts.dataflow` (C) is left untouched.

**Rationale**: additive (Principle VI); language-neutral; the portable rule and,
later, other rules read `function.taint_paths`.

## D5. The portable rule

**Decision**: `core/rules/portable/tainted_input_unguarded_sink.py` — for each
function, for each `taint_path` with `guarded == False`, emit one finding with
`confidence='medium'`, evidence = the source + sink statements/lines, and a
remediation hint to validate input before the sink. Registered in BOTH the
Solidity and C rule registries under a new task id (next free per registry).

**Rationale**: the headline new dataflow capability, portable across languages,
honestly medium confidence (Principle II). One finding per unguarded path.

## D6. Determinism + bound

**Decision**: deterministic iteration (statement order; sorted outputs where a
set is involved); per-function work is O(statements x tainted-set) with a small
cap on tracked names to bound pathological inputs.

**Rationale**: FR-007/SC-003.

## D7. Honesty + tests

**Decision**: KNOWN_QUIRKS entry (intra-procedural only; FP from token matching;
FN from aliasing/cross-function). Tests: synthetic taint pass (unguarded path
found, guarded path flagged guarded, no-flow silent, deterministic); portable
rule (fires unguarded, silent guarded/no-flow); an invocation test enumerating
the 5 `requires_dataflow` rules and asserting each `run(context)` returns without
error and is in the registry; full-suite regression (SC-005).

**Rationale**: Principle VII; directly verifies SC-001..SC-006.
