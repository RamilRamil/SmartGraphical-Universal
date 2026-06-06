# Quickstart / Verification: Structural graph diff

## 0. Baseline

```bash
cd SmartGraphical
.venv/bin/python -m pytest -q     # expect 498 passed (post-017), 12 skipped
```

## 1. Implement

- `services/graph_diff.py::diff_graph_payloads`
- `HistoryService.diff_graphs`
- route `GET /scans/{id}/graph-diff/{other}`

## 2. Pure-diff unit tests (US1 core)

```bash
.venv/bin/python -m pytest tests/unit/test_graph_diff.py -q
```
Covers: added/removed/changed nodes; added/removed edges; positional-edge-id-only
⇒ unchanged (SC-005); identical graphs ⇒ empty (SC-002); missing payload ⇒
`graph_available: false` (FR-005); deterministic sorted output.

## 3. History integration (US1)

```bash
.venv/bin/python -m pytest tests/unit/test_history_service_graph_diff.py -q
```
Two `run_all` scans of the same fixture diff cleanly; different-artifact ⇒
`ERROR_DIFF_MISMATCH`; missing scan ⇒ `ERROR_NOT_FOUND`; single-rule scan (no
graph) ⇒ `graph_available: false`.

## 4. HTTP contract (US2)

```bash
.venv/bin/python -m pytest tests/integration/test_http_graph_diff.py -q
```
`GET /scans/{id}/graph-diff/{other}` returns the diff JSON; mismatch/not-found
mirror the findings-diff contract.

## 5. No regression to existing diff / payload

```bash
.venv/bin/python -m pytest tests/unit/test_history_service.py tests/integration/test_http_contract.py -q
```

## 6. Full regression (SC-004)

```bash
.venv/bin/python -m pytest -q     # expect >= 498 + new tests, 0 failed
```

## Done when

- Pure-diff + history + HTTP tests green (US1, US2)
- Identical graphs ⇒ empty diff (SC-002); positional edge ids ignored (SC-005)
- Error contract matches findings diff (SC-003)
- Full suite green (SC-004)
- (US3 frontend DiffPage visualization — separate increment, not in this slice)
```
