# Quickstart: Verify State Read/Write Fix

**Feature**: `001-fix-solidity-state-writes`

## Prerequisites

- Python env with project dependencies installed
- Optional: frontend dev server for graph UI

## 1. Run targeted unit tests (after implementation)

```bash
python -m pytest tests/unit/test_solidity_state_access.py -q
python -m pytest tests/unit/test_serializers.py -q
python -m pytest tests/unit/test_rules_state_mutation.py -q
```

## 2. Analyze KeeperRewards fixture

From repo root, use the project's existing Solidity ingest path (CLI or API) on:

`examples/keeper/KeeperRewards.sol`

Expected graph checks:

| Function | `state_writes` mentions `rewards` | `state_to_function_write` from `rewards` |
|----------|-----------------------------------|--------------------------------------------|
| `isCollateralized` | No | No |
| `canHarvest` | No | No |
| `isHarvestRequired` | No | No |
| `canUpdateRewards` | No | No |
| `harvest` | Yes | Yes |
| `_collateralize` | Yes | Yes |

Expected read edges:

- `isCollateralized`, `canHarvest`, `isHarvestRequired` → `state_to_function_read` from `rewards`

## 3. UI smoke (frontend)

1. Upload / open graph for `KeeperRewards`.
2. Select state node `rewards`:
   - **Readers** lists view helpers + `harvest` (reads before write).
   - **Writers** lists only `harvest` and `_collateralize` (if visible on graph).
3. Enable state-write highlight:
   - View functions are **not** highlighted as writers.

## 4. Rules smoke

Run Solidity rule pack on the same artifact. Confirm no rule cites `rewards` mutation inside `isCollateralized` / `isHarvestRequired`.

## 5. Schema version

Response JSON should include `"graph_schema_version": "1.1"` after release.
