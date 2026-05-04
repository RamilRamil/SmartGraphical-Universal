"""Rule-level tests for `ordering` on a synthetic normalized model."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.solidity.ordering import run as run_ordering


def _context_with_function(statements):
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name="Vault", kind="contract_like")
    type_entry.functions.append(NormalizedFunction(
        name="handle",
        owner="Vault",
        exploration_statements=list(statements),
    ))
    model.types.append(type_entry)
    return AnalysisContext(
        path="x.sol", language="solidity", reader=None, lines=[],
        unified_code="", rets=[], hierarchy={}, high_connections=[],
        normalized_model=model,
    )


class OrderingRuleTests(unittest.TestCase):

    def test_transfer_without_preceding_fetch_alerts(self):
        context = _context_with_function([
            "uint amount = bids[msg.sender]",
            "payable(msg.sender).transfer(amount)",
        ])
        findings = run_ordering(context)
        self.assertTrue(any("fetch function did not occur before transfer" in f.message for f in findings))

    def test_fetch_followed_by_transfer_is_clean(self):
        context = _context_with_function([
            "rebase()",
            "payable(msg.sender).transfer(amount)",
        ])
        findings = run_ordering(context)
        self.assertEqual(findings, [])

    def test_fetch_without_trailing_transfer_alerts(self):
        context = _context_with_function([
            "rebase()",
            "x = 1",
        ])
        findings = run_ordering(context)
        self.assertTrue(any("transfer function did not occur after fetch" in f.message for f in findings))

    def test_unrelated_statements_produce_no_alerts(self):
        context = _context_with_function([
            "x = 1",
            "y = 2",
            "emit Event(x)",
        ])
        findings = run_ordering(context)
        self.assertEqual(findings, [])

    def test_finding_metadata_is_populated(self):
        context = _context_with_function([
            "payable(msg.sender).transfer(amount)",
        ])
        findings = run_ordering(context)
        self.assertTrue(findings)
        finding = findings[0]
        self.assertEqual(finding.task_id, "8")
        self.assertEqual(finding.rule_id, "check_order")
        self.assertEqual(finding.category, "FlowAndOrdering")


if __name__ == "__main__":
    unittest.main()
