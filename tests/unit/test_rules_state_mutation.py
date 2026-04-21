"""Rule-level tests for `state_mutation` (unallowed_manipulation + pool_interactions)."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedGuardFact,
    NormalizedType,
)
from smartgraphical.core.rules.state_mutation import (
    run_pool_interactions,
    run_unallowed_manipulation,
)


def _context_with_function(**overrides):
    function = NormalizedFunction(
        name=overrides.pop("name", "setFee"),
        owner="Vault",
        visibility=overrides.pop("visibility", "external"),
        is_entrypoint=overrides.pop("is_entrypoint", True),
        inputs=overrides.pop("inputs", [["uint", "amount"]]),
        mutations=overrides.pop("mutations", ["fee = amount"]),
        guard_facts=overrides.pop("guard_facts", []),
        guards=overrides.pop("guards", []),
        entrypoint_permissions=overrides.pop("entrypoint_permissions", []),
        exploration_statements=overrides.pop("exploration_statements", []),
    )
    assert not overrides, f"Unexpected overrides: {overrides}"
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name="Vault", kind="contract_like")
    type_entry.functions.append(function)
    model.types.append(type_entry)
    return AnalysisContext(
        path="x.sol", language="solidity", reader=None, lines=[],
        unified_code="", rets=[], hierarchy={}, high_connections=[],
        normalized_model=model,
    )


class UnallowedManipulationTests(unittest.TestCase):

    def test_sensitive_mutation_without_guards_alerts(self):
        context = _context_with_function(mutations=["balance = amount"])
        findings = run_unallowed_manipulation(context)
        self.assertTrue(findings)
        self.assertIn("sensitive state", findings[0].message)

    def test_guarded_sensitive_mutation_is_silent(self):
        context = _context_with_function(
            mutations=["balance = amount"],
            guard_facts=[NormalizedGuardFact("require", "msg.sender == owner")],
        )
        self.assertEqual(run_unallowed_manipulation(context), [])

    def test_permissioned_sensitive_mutation_is_silent(self):
        context = _context_with_function(
            mutations=["balance = amount"],
            entrypoint_permissions=["onlyOwner"],
        )
        self.assertEqual(run_unallowed_manipulation(context), [])

    def test_non_sensitive_mutation_is_silent(self):
        context = _context_with_function(
            mutations=["counter = value"],
            inputs=[["uint", "value"]],
        )
        self.assertEqual(run_unallowed_manipulation(context), [])

    def test_empty_inputs_skip_rule(self):
        context = _context_with_function(
            mutations=["balance = 1"],
            inputs=[],
        )
        self.assertEqual(run_unallowed_manipulation(context), [])


class PoolInteractionsTests(unittest.TestCase):

    def test_external_mint_without_permissions_alerts(self):
        context = _context_with_function(
            name="mintTokens",
            visibility="external",
            entrypoint_permissions=[],
            guard_facts=[],
        )
        messages = [f.message for f in run_pool_interactions(context)]
        self.assertTrue(any("is external without explicit permissions" in m for m in messages))

    def test_mint_with_permissions_does_not_alert_on_access(self):
        context = _context_with_function(
            name="mintTokens",
            visibility="external",
            entrypoint_permissions=["onlyOwner"],
            guard_facts=[],
        )
        messages = [f.message for f in run_pool_interactions(context)]
        self.assertFalse(any("is external without explicit permissions" in m for m in messages))

    def test_burn_with_zero_address_in_statements_alerts(self):
        context = _context_with_function(
            name="burnTokens",
            visibility="external",
            entrypoint_permissions=["onlyOwner"],
            exploration_statements=["transfer(address(0), amount)"],
        )
        messages = [f.message for f in run_pool_interactions(context)]
        self.assertTrue(any("zero address is used" in m for m in messages))

    def test_unrelated_function_is_ignored(self):
        context = _context_with_function(name="unrelated")
        self.assertEqual(run_pool_interactions(context), [])


if __name__ == "__main__":
    unittest.main()
