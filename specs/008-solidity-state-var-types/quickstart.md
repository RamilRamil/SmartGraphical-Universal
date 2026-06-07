# Quickstart: MultiStateFields state nodes

## Verify

```bash
python3 -m unittest tests.unit.test_solidity_state_variables -v
```

## UI

1. Rebuild Docker if used: `docker compose build --no-cache smartgraphical`
2. Run a **new scan** on `tests/fixtures/solidity/MultiStateFields.sol` (graph is cached per scan).
3. Open graph: state workspace should list `_donatedAssets`, `_totalShares`, `_exitQueue`, mappings, etc.
