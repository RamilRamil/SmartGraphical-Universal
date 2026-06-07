# Quickstart: Function call flow (after implementation)

## Manual

1. Open a scan graph; select a **function** node (e.g. `updateStateAndDeposit`).
2. In the side panel, click **Call flow**.
3. Modal opens: root centered; upstream callers left (or above), callees right (or below) per layout.
4. Default: **Both**, depth **2**. Use **Expand full chain** for unlimited upstream+downstream (within cap).
5. Toggle **Show external contract calls** to hide `cross_contract_call` if needed.
6. Close modal; main graph unchanged.

## Automated (when T001 done)

```bash
cd frontend && npm test -- buildCallFlowSubgraph
```

## Verify call direction

Use a scan created **after** spec 007 fix. In downstream mode, callees must appear as arrows **from** root **to** callee.
