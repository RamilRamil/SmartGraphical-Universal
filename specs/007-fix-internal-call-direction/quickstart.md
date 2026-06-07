# Quickstart: Verify internal call direction

## Automated

```bash
python -m unittest tests.unit.test_solidity_internal_call_direction -v
python -m unittest tests.unit.test_solidity_inheritance_calls -v
```

## Manual (ImportModifierFixture)

1. Load `tests/fixtures/solidity/ImportModifierFixture.sol` on the graph tab.
2. Select `updateStateAndDeposit`.
3. Confirm internal arrow goes **to** `deposit`, not **from** `deposit`.
4. Side panel: caller should list outgoing internal call to `deposit`.
