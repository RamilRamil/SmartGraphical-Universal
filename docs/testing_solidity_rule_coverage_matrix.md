# Solidity rule coverage matrix (model-level)

Registry: `smartgraphical/adapters/solidity/adapter.py` (`build_rule_registry`).

| task_id | rule_id | Unit test module (synthetic model / legacy `rets`) |
|--------|---------|-----------------------------------------------------|
| 1 | contract_version | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 2 | unallowed_manipulation | `tests/unit/test_rules_state_mutation.py` |
| 3 | staking | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 4 | pool_interactions | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 5 | local_points | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 6 | exceptions | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 7 | complicated_calculations | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 8 | check_order | `tests/unit/test_rules_ordering.py` |
| 9 | withdraw_check | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 10 | similar_names | `tests/unit/test_rules_solidity_normalized_coverage.py` |
| 11 | outer_calls | `tests/unit/test_rules_outer_calls.py` |

Adapter fixtures (small `.sol` under `tests/fixtures/solidity/`):

| Fixture | Checked in |
|---------|------------|
| `MinimalGuard.sol` | `tests/integration/test_solidity_adapter_fixtures.py` |
| `ExternalMint.sol` | same |
| `WithdrawNoGuard.sol` | same |
| `MixedMath.sol` | same |

End-to-end invariant on one reference contract: `tests/integration/test_full_pipeline.py` (expects repo-root `SimpleAuction.sol`).
