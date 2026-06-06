# Contract: structural graph diff

## Pure core

```python
# smartgraphical/services/graph_diff.py
def diff_graph_payloads(payload_a: dict | None, payload_b: dict | None) -> dict: ...
```
- Reads nodes/edges from `payload["model_summary"]["graph"]` defensively.
- Returns the graph-diff result dict (see data-model.md), WITHOUT the
  scan/artifact ids (those are attached by the history layer). `graph_available`
  is `false` when either payload is missing/None or lacks a graph.
- Deterministic: lists sorted by identity key.

## History method

```python
# smartgraphical/services/history_service.py
class HistoryService:
    def diff_graphs(self, scan_a_id, scan_b_id) -> dict: ...
```
- Reuses scan lookup + `ERROR_NOT_FOUND` and the same-artifact `ERROR_DIFF_MISMATCH`
  guard exactly as `diff_scans`.
- Loads each scan's graph via `get_graph`, calls `diff_graph_payloads`, and
  augments the result with `scan_a_id`, `scan_b_id`, `artifact_id`.

## HTTP endpoint

```text
GET /scans/{scan_id}/graph-diff/{other_id}
-> 200 graph-diff JSON (data-model.md shape)
-> error contract identical to GET /scans/{scan_id}/diff/{other_id}
   (mismatched artifacts, missing scan)
```

## Invariants

1. Identical graphs ⇒ all added/removed/changed empty; only `unchanged_node_count`
   > 0 (SC-002).
2. Edge matching ignores positional `edge:N` ids (SC-005).
3. No change to the findings diff, the stored graph payload, or any existing
   endpoint (FR-007).
4. Same-artifact + not-found error contract identical to findings diff (SC-003).

## Verification

- `tests/unit/test_graph_diff.py`: synthetic payloads — added/removed/changed
  nodes; added/removed edges; positional-edge-id-only change ⇒ unchanged;
  identical graphs ⇒ empty; missing payload ⇒ `graph_available: false`;
  determinism (sorted output).
- `tests/unit/test_history_service_graph_diff.py`: two `run_all` scans of the same
  fixture diff cleanly; different-artifact ⇒ `ERROR_DIFF_MISMATCH`; missing scan ⇒
  `ERROR_NOT_FOUND`; a single-rule scan (no graph) ⇒ `graph_available: false`.
- `tests/integration/test_http_graph_diff.py`: endpoint returns the JSON and the
  mismatch error contract.
