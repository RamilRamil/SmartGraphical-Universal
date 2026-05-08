"""Unit tests for min_slippage_bounds (task 14) on synthetic call_edges."""
import unittest

from smartgraphical.core.model import AnalysisContext, NormalizedArtifact, NormalizedAuditModel, NormalizedCallEdge, NormalizedType
from smartgraphical.core.rules.solidity.min_slippage_bounds import run as run_min_slippage_bounds


def _context_with_edges(call_edges):
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact, call_edges=call_edges)
    model.types.append(NormalizedType(name="C", kind="contract_like"))
    return AnalysisContext(
        path="x.sol",
        language="solidity",
        reader=None,
        lines=[],
        unified_code="",
        rets=[],
        hierarchy={},
        high_connections=[],
        normalized_model=model,
    )


class MinSlippageBoundsRuleTests(unittest.TestCase):

    def test_zero_min_shares_literal_on_addliquidity_triggers(self):
        edge = NormalizedCallEdge(
            "C",
            "zap",
            "C",
            "addLiquidity",
            "function_to_function",
            callsite="pool.addLiquidity(balances, minAmounts, 0)",
            args_map=[
                {"param": "amounts", "value": "balances", "source_kind": "local"},
                {"param": "minAmounts", "value": "minAmounts", "source_kind": "local"},
                {"param": "minShares", "value": "0", "source_kind": "literal"},
            ],
            line_numbers=[42],
        )
        ctx = _context_with_edges([edge])
        findings = run_min_slippage_bounds(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].task_id, "14")
        self.assertEqual(findings[0].rule_id, "min_slippage_bounds")
        self.assertIn("addLiquidity", findings[0].message)
        self.assertIn("minShares=0", findings[0].message)

    def test_positional_last_arg_zero_on_addliquidity_triggers(self):
        edge = NormalizedCallEdge(
            "C",
            "zap",
            "C",
            "addLiquidity",
            "function_to_function",
            callsite="pool.addLiquidity(balances, minAmounts, 0)",
            args_map=[
                {"param": "arg0", "value": "balances", "source_kind": "local"},
                {"param": "arg1", "value": "minAmounts", "source_kind": "local"},
                {"param": "arg2", "value": "0", "source_kind": "literal"},
            ],
            line_numbers=[9],
        )
        ctx = _context_with_edges([edge])
        findings = run_min_slippage_bounds(ctx)
        self.assertEqual(len(findings), 1)

    def test_non_literal_does_not_trigger(self):
        edge = NormalizedCallEdge(
            "C",
            "zap",
            "C",
            "addLiquidity",
            "function_to_function",
            args_map=[
                {"param": "minShares", "value": "userMin", "source_kind": "input"},
            ],
        )
        ctx = _context_with_edges([edge])
        findings = run_min_slippage_bounds(ctx)
        self.assertEqual(findings, [])

    def test_non_risk_callee_does_not_trigger(self):
        edge = NormalizedCallEdge(
            "C",
            "foo",
            "C",
            "transfer",
            "function_to_function",
            args_map=[
                {"param": "amount", "value": "0", "source_kind": "literal"},
            ],
        )
        ctx = _context_with_edges([edge])
        findings = run_min_slippage_bounds(ctx)
        self.assertEqual(findings, [])

    def test_deadline_zero_literal_triggers(self):
        edge = NormalizedCallEdge(
            "C",
            "trade",
            "C",
            "exactInputSingle",
            "function_to_function",
            args_map=[
                {"param": "params", "value": "p", "source_kind": "local"},
                {"param": "deadline", "value": "0", "source_kind": "literal"},
            ],
            line_numbers=[3],
        )
        ctx = _context_with_edges([edge])
        findings = run_min_slippage_bounds(ctx)
        self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
