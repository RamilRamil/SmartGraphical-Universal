# Phase 1 Data Model: Intra-Procedural Taint

In-memory, additive. No persistence.

## New field: NormalizedFunction.taint_paths

Add to `smartgraphical/core/model.py::NormalizedFunction`:

```python
taint_paths: list = field(default_factory=list)
```

Additive, default empty; populated by the core taint pass. Functions that have no
source->sink flow keep `[]` (consumers that ignore it are unaffected).

## Entity: TaintPath (dict)

One recorded intra-procedural source->sink reachability:

| Field | Meaning |
|-------|---------|
| `source` | the tainted origin name (a parameter, or the LHS that received an untrusted read) |
| `sink` | a short description / token of the sensitive sink |
| `source_index` | statement index where the taint enters (informational) |
| `sink_index` | statement index of the sink |
| `source_stmt` | the source statement text (evidence) |
| `sink_stmt` | the sink statement text (evidence) |
| `guarded` | bool — a guard (require/if/assert referencing the tainted name, or a `guard_fact`) appears at/before the sink |

## Heuristic vocabulary (tunable constants)

- **Source tokens** (untrusted reads): `recv`, `recvfrom`, `read`, `packet`,
  `deserialize`, `decode`, `parse`, `calldata`, `msg.data`.
- **Sink tokens** (sensitive): `transfer`, `send`, `write`, `store`, `memcpy`,
  plus any statement that assigns to a name in `function.mutations`.
- Plus: function parameters (`function.inputs`) seed the initial tainted set;
  `function.guard_facts` and `require`/`if`/`assert` statements provide guards.

## Propagation (state)

```text
tainted := set(function.inputs)
for stmt in statements(function):     # exploration_statements, else body split
    if assignment(stmt) and rhs_references_tainted_or_source(stmt):
        tainted.add(lhs(stmt))
    elif reassigned_to_constant(stmt):
        tainted.discard(lhs(stmt))
    if is_sink(stmt) and references_tainted(stmt):
        record TaintPath(source, sink, indices, stmts, guarded=guard_seen_for(name))
```

Bounded: cap the tracked `tainted` set size; linear over statements; deterministic.

## Consumers

- **Portable rule** `tainted_input_unguarded_sink`: emits a `confidence='medium'`
  finding per `taint_path` with `guarded == False`; evidence = source_stmt +
  sink_stmt + line numbers (via the engine's evidence inference).
- (Future) existing rules may read `taint_paths`; out of scope for v1.

## Validation rules

- `taint_paths` MUST be additive — no existing finding/graph/contract changes
  (SC-005).
- A guarded flow MUST NOT be reported by the portable rule (FR-003).
- Findings MUST carry confidence <= medium (FR-006).
- The pass MUST be deterministic and bounded (FR-007).
