# Contract: Taint pass + portable rule

## Core module: `smartgraphical/core/dataflow/taint.py`

```python
def compute_taint(function) -> list[dict]:
    """Intra-procedural taint over one NormalizedFunction's facts.
    Returns a list of TaintPath dicts (source, sink, *_index, *_stmt, guarded).
    Pure, deterministic, bounded; no AST. See data-model.md."""

def apply_taint(model) -> None:
    """Set function.taint_paths = compute_taint(function) for every function in
    model.types. Idempotent; additive."""
```

- **R1 (pure/deterministic)**: same `NormalizedFunction` in -> identical
  `taint_paths` out; statement order preserved; outputs sorted where a set is
  involved.
- **R2 (no AST/dep)**: uses only `function.inputs`, `exploration_statements`/
  `body`, `mutations`, `guard_facts`, and regex token matching.
- **R3 (additive)**: only sets the new `taint_paths` field; touches nothing else.
- **R4 (bounded)**: linear in statements; tracked-name set capped.

## Wiring

`smartgraphical/services/analysis_service.py::AnalysisService.analyze` calls
`apply_taint(context.normalized_model)` after `adapter.parse_source(...)`, before
returning the context — one seam for every language.

## Portable rule: `core/rules/portable/tainted_input_unguarded_sink.py`

```python
_META = dict(
    task_id=<new id per registry>, slug="tainted_input_unguarded_sink",
    title="Untrusted input reaches a sensitive sink without a guard",
    category="dataflow", portability="portable", confidence="medium",
    remediation_hint="Validate/guard untrusted input before it reaches the sink.",
)

def run(context) -> list[Finding]:
    """One medium-confidence finding per function taint_path with guarded == False;
    evidence = source_stmt + sink_stmt."""
```

- **B1**: fires only for `guarded == False` taint paths (FR-002/FR-003).
- **B2**: `confidence == "medium"` (FR-006); never higher.
- **B3**: registered in BOTH the Solidity and C rule registries under the next
  free task id; portable (reads only `function.taint_paths`).
- **B4**: silent when a function has no taint paths or all are guarded.

## `requires_dataflow` invocation (US3, reframed)

- The 5 catalog rules marked `requires_dataflow: true` are already registered and
  executed; a test enumerates them and asserts each is in the registry and its
  `run(context)` completes without error on a fixture (proving "0 silently
  skipped", SC-002), and that adding `taint_paths` does not change their output
  (additive).

## Honesty

- KNOWN_QUIRKS entry: intra-procedural only; token-match false positives;
  aliasing/cross-function false negatives; medium-confidence ceiling.
