# Data Model: Structural graph diff

No persistence change. Entities below are the inputs/outputs of the diff.

## Input — Graph payload (existing, unchanged)

Stored per scan as `graph.json` (= `web_api.graph` output):
```text
{ "status", "artifact", "language", "duration_ms",
  "model_summary": { ..., "graph": { "graph_schema_version", "nodes": [...], "edges": [...] } } }
```
- **Node**: `{ "id", "group", "label", "kind", ... }` — `id` is canonical/stable.
- **Edge**: `{ "id" (positional, ignored), "source", "target", "kind", "label", ... }`.

## Output — Graph diff result (new, JSON-safe)

```text
{
  "scan_a_id": int,
  "scan_b_id": int,
  "artifact_id": int,
  "graph_available": bool,        # false if either side has no graph payload
  "added_nodes":   [ {id, group, label, kind}, ... ],
  "removed_nodes": [ {id, group, label, kind}, ... ],
  "changed_nodes": [ {id, before:{group,label,kind}, after:{group,label,kind}}, ... ],
  "added_edges":   [ {source, target, kind, label}, ... ],
  "removed_edges": [ {source, target, kind, label}, ... ],
  "added_node_count": int,
  "removed_node_count": int,
  "changed_node_count": int,
  "added_edge_count": int,
  "removed_edge_count": int,
  "unchanged_node_count": int
}
```

## Identity & classification rules

| Entity | Identity key | Added | Removed | Changed |
|--------|-------------|-------|---------|---------|
| Node | `id` | in B, not A | in A, not B | id in both, `(group,label,kind)` differs |
| Edge | `(source, target, kind)` | in B, not A | in A, not B | n/a (kind in key ⇒ a kind change is remove+add) |

- Edge `id` (`edge:N`) is positional and MUST NOT participate in matching.
- All lists sorted by their identity key for deterministic output.
- Missing graph on either side → all lists empty, `graph_available: false`.

## Validation rules

- Same-artifact guard (reused from findings diff): diff only between two scans of
  the same artifact, else `ERROR_DIFF_MISMATCH`.
- Missing scan → `ERROR_NOT_FOUND` (reused).
- Output is JSON-safe (plain dicts/lists/strings/ints).
