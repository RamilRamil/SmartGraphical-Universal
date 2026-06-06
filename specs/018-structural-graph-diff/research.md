# Research: Structural graph diff

Phase 0 — no open `NEEDS CLARIFICATION`. Decisions below; the design mirrors the
existing findings diff.

## Decision 1 — Node identity = canonical `id`; edge identity = `(source,target,kind)`

**Decision**: Match nodes across scans by the canonical `id`
(`type:`/`function:`/`state:`/`tile:`/`external:` …). Match edges by the semantic
triple `(source, target, kind)`. Do NOT use the edge `id`.

**Rationale**: After feature 017 node ids are canonical and stable across scans of
the same artifact — the natural identity. The stored edge `id` is positional
(`edge:0`, `edge:1`, …) and changes whenever node/edge ordering shifts, so using
it would report spurious add/remove churn. `(source,target,kind)` is the stable
semantic identity. Captured as FR-003/SC-005.

**Alternatives considered**:
- Edge id as identity — rejected (positional, unstable).
- Label-sensitive edge identity — rejected for the key (labels are often empty/
  cosmetic); label can be shown in descriptors but not used for matching.

## Decision 2 — "Changed" tracks `(group, label, kind)` only

**Decision**: A node is "changed" when its id persists but `group`, `label`, or
`kind` differs; the entry carries before/after.

**Rationale**: These three are the stable, meaningful structural attributes.
Deeper fact-field/line-number diffing would be noisy and is out of scope (recorded
in spec Assumptions). Keeps the diff legible and deterministic.

## Decision 3 — Pure core + thin history method (mirror findings diff)

**Decision**: Put the algorithm in a pure `services/graph_diff.py`
(`diff_graph_payloads`), and a thin `HistoryService.diff_graphs` that loads stored
payloads via `get_graph`, applies the existing same-artifact guard
(`ERROR_DIFF_MISMATCH`) and not-found error, then calls the pure core.

**Rationale**: Matches the project's pure-function pattern (`correlateFindings`,
`benchmark/corpus`) for trivial unit testing, and reuses the findings-diff guards
verbatim so the two diffs behave consistently (Principle VI).

## Decision 4 — Missing graph degrades, never raises

**Decision**: If either scan lacks a graph payload (`get_graph` → None, e.g. a
single-rule scan), return an empty diff with `graph_available: false` instead of
raising.

**Rationale**: Single-rule scans legitimately have no graph; the caller/UI should
get a clear "no graph to compare" signal, not an error (Principle II). The
not-found / mismatch errors remain reserved for genuinely invalid scan pairs.

## Decision 5 — Determinism

**Decision**: Emit added/removed/changed lists in a stable, sorted order (by node
id / edge triple) so output is deterministic regardless of dict/set iteration
order.

**Rationale**: SC-002 requires deterministic results; also avoids the kind of
hash-seed nondeterminism found in feature 015. Sorting by the canonical keys is
cheap and stable.

## Open risks

- A future graph schema change could rename node attributes; the diff reads
  `group`/`label`/`kind` defensively via `.get`, defaulting to "" so a missing
  attribute is simply treated as empty (no crash).
- Bundle graphs may carry many nodes; the diff is O(n+m) with dict lookups, fine
  at expected sizes.
