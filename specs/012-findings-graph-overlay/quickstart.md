# Quickstart: Validate Feature 012

Frontend feature. From `frontend/`: `npm install` once, then `npm run test`
(Vitest) and `npm run dev` (against the API on :8765) for manual checks.

## 1. Unit-test the correlation module (US1/US2/US5 core)

```bash
cd frontend
npm run test -- correlateFindings
```

Asserts the matrix in `contracts/correlation-module.md`: Solidity/C/Rust matches,
mixed-confidence aggregation (max + count), multi-match, and unmapped.

## 2. Manual: see findings on the graph (US1)

- Run a `task = all` scan on a contract with findings (e.g. `ImportModifierFixture.sol`).
- Open Scan detail → Graph tab.
- Confirm: function/contract nodes that own findings show a count badge and a
  color by highest confidence; a low-only node is visibly muted vs a high node;
  nodes without findings have no badge.

## 3. Manual: jump from finding to node (US2)

- On the Findings tab, click "Show on graph" on a finding that names a function.
- Confirm the Graph tab opens with that node centered and highlighted.
- Click "Show on graph" on a finding whose evidence has no type/function — confirm
  an explicit "not locatable on the graph" message (no silent no-op).

## 4. Manual: filter to the suspicious surface (US3)

- On the Graph tab, enable "Only nodes with findings".
- Confirm only finding-owning nodes remain; enable "include neighbors" and confirm
  directly connected nodes reappear; on a scan with zero findings confirm an
  explicit empty state.

## 5. Manual: node → its findings (US4)

- Select a finding-owning node on the graph.
- Confirm the side panel lists that node's findings (title/category/confidence);
  select a node without findings and confirm it says so.

## 6. Regression

```bash
cd frontend
npm run test        # all Vitest green, including existing graph modules
npm run typecheck   # tsc --noEmit clean
```

Confirm a pre-existing scan with no overlay props still renders the graph exactly
as before (B5 back-compat).
