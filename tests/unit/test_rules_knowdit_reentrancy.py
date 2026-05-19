"""Unit tests for Knowdit-style reentrancy tasks 13-15 (normalized model)."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.solidity.knowdit_reentrancy import (
    run_bridge_retry_gap,
    run_read_only_oracle_gap,
    run_unstake_share_order,
)


def _ctx(fn: NormalizedFunction):
    artifact = NormalizedArtifact(path="t.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    t = NormalizedType(name="C", kind="contract_like")
    t.functions.append(fn)
    model.types.append(t)
    return AnalysisContext(
        path="t.sol", language="solidity", reader=None, lines=[],
        unified_code="", rets=[], hierarchy={}, high_connections=[],
        normalized_model=model,
    )


class ReadOnlyOracleGapTests(unittest.TestCase):

    def test_reserve_then_transfer_then_sync_flags(self):
        fn = NormalizedFunction(
            name="removeLiq",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "reserve0 -= amount0",
                "token.transfer(msg.sender, amount0)",
                "sync()",
            ],
        )
        findings = run_read_only_oracle_gap(_ctx(fn))
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, "13")
        self.assertEqual(findings[0].rule_id, "read_only_oracle_reentrancy")

    def test_sync_before_transfer_is_clean(self):
        fn = NormalizedFunction(
            name="ok",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "reserve0 -= amount0",
                "sync()",
                "token.transfer(msg.sender, amount0)",
            ],
        )
        self.assertEqual(run_read_only_oracle_gap(_ctx(fn)), [])

    def test_skips_non_entrypoint(self):
        fn = NormalizedFunction(
            name="internalRemove",
            owner="C",
            is_entrypoint=False,
            exploration_statements=[
                "reserve0 -= amount0",
                "token.transfer(msg.sender, amount0)",
                "sync()",
            ],
        )
        self.assertEqual(run_read_only_oracle_gap(_ctx(fn)), [])


class BridgeRetryGapTests(unittest.TestCase):

    def test_external_before_processed_flags(self):
        fn = NormalizedFunction(
            name="retryBridge",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "token.transfer(msg.sender, amount)",
                "processed[id] = true",
            ],
        )
        findings = run_bridge_retry_gap(_ctx(fn))
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, "14")

    def test_processed_before_transfer_clean(self):
        fn = NormalizedFunction(
            name="retryBridge",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "processed[id] = true",
                "token.transfer(msg.sender, amount)",
            ],
        )
        self.assertEqual(run_bridge_retry_gap(_ctx(fn)), [])

    def test_no_bridge_context_skipped(self):
        fn = NormalizedFunction(
            name="retrySomething",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "token.transfer(msg.sender, amount)",
                "done = true",
            ],
        )
        self.assertEqual(run_bridge_retry_gap(_ctx(fn)), [])


class UnstakeShareOrderTests(unittest.TestCase):

    def test_payout_before_burn_flags(self):
        fn = NormalizedFunction(
            name="unstake",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "uint r = rewardFor(msg.sender)",
                "token.transfer(msg.sender, r)",
                "_burn(msg.sender, shares)",
            ],
        )
        findings = run_unstake_share_order(_ctx(fn))
        self.assertTrue(findings)
        self.assertEqual(findings[0].task_id, "15")

    def test_burn_before_payout_clean(self):
        fn = NormalizedFunction(
            name="unstake",
            owner="C",
            is_entrypoint=True,
            exploration_statements=[
                "_burn(msg.sender, shares)",
                "token.transfer(msg.sender, reward)",
            ],
        )
        self.assertEqual(run_unstake_share_order(_ctx(fn)), [])


if __name__ == "__main__":
    unittest.main()
