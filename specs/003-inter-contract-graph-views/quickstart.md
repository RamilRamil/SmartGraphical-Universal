# Quickstart: Verify Inter-Contract Graph Views

**Feature**: `003-inter-contract-graph-views`

## Prerequisites

- Frontend dev server or built UI
- Keeper bundle at `examples/keeper/` (folder upload with manifest)

## 1. Unit tests

From repo root (if npm test is configured for frontend):

```bash
cd frontend && npm test -- interContractOverview
```

Or run Vitest on `frontend/src/graph/interContractOverview.test.ts`.

Expected: tests **drops bundle_import when cross_type_call already links the pair** and **keeps bundle_import when no semantic cross-type edge exists** pass.

## 2. UI smoke - full graph

1. Load `examples/keeper/` as Solidity bundle.
2. Stay on **Full graph** (not Inter-contract).
3. Confirm **no** red arrow `extends KeeperOracles` between `KeeperValidators` and `KeeperOracles` contract boxes.
4. Click contract nodes: side panel must not offer `Edge (cross_type_call) ... extends KeeperOracles` for that pair.
5. Toggle **Show cross-contract calls** off: no `extends` between bundle contracts.
6. Toggle **Show cross-contract calls** on: still **no** `extends KeeperRewards` between type nodes; optional function-level cross-type (e.g. `approveValidators` -> `_collateralize`) may appear.
7. **Inter-contract**: `extends` between contracts visible.

## 3. UI smoke - inter-contract

1. Switch to **Inter-contract**.
2. Between `KeeperValidators` and `KeeperOracles`: one semantic link (`extends KeeperOracles` or aggregated cross-type), **not** a second `solidity_import` / `bundle_import` arrow.
3. External-calls toolbar button should be disabled.

## 4. Regression with 002

Inheritance call direction (`approveValidators` -> `_collateralize`) is unchanged; see `specs/002-inheritance-cross-calls/quickstart.md` (backend) and full-graph internal edges for that call.
