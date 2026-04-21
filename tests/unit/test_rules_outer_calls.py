"""Rule-level tests for `outer_calls` on a synthetic normalized model."""
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.outer_calls import run as run_outer_calls


def _context_with_function(**overrides):
    function = NormalizedFunction(
        name=overrides.pop("name", "openDoor"),
        owner="Gate",
        visibility=overrides.pop("visibility", "external"),
        is_entrypoint=overrides.pop("is_entrypoint", True),
        inputs=overrides.pop("inputs", [["address", "user"]]),
        mutations=overrides.pop("mutations", ["owner = user"]),
        guard_facts=overrides.pop("guard_facts", []),
        guards=overrides.pop("guards", []),
        entrypoint_permissions=overrides.pop("entrypoint_permissions", []),
    )
    assert not overrides, f"Unexpected overrides: {overrides}"
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name="Gate", kind="contract_like")
    type_entry.functions.append(function)
    model.types.append(type_entry)
    return AnalysisContext(
        path="x.sol", language="solidity", reader=None, lines=[],
        unified_code="", rets=[], hierarchy={}, high_connections=[],
        normalized_model=model,
    )


class OuterCallsRuleTests(unittest.TestCase):

    def test_external_unguarded_mutating_function_triggers_alert(self):
        context = _context_with_function()
        findings = run_outer_calls(context)
        self.assertEqual(len(findings), 1)
        self.assertIn("Outer manipulation", findings[0].message)

    def test_entrypoint_permissions_silence_the_rule(self):
        context = _context_with_function(entrypoint_permissions=["onlyOwner"])
        findings = run_outer_calls(context)
        self.assertEqual(findings, [])

    def test_explicit_guard_facts_silence_the_rule(self):
        from smartgraphical.core.model import NormalizedGuardFact
        context = _context_with_function(
            guard_facts=[NormalizedGuardFact(guard_type="require", expression="user != address(0)")],
        )
        findings = run_outer_calls(context)
        self.assertEqual(findings, [])

    def test_public_visibility_is_ignored(self):
        context = _context_with_function(visibility="public")
        findings = run_outer_calls(context)
        self.assertEqual(findings, [])

    def test_empty_inputs_are_ignored(self):
        context = _context_with_function(inputs=[])
        findings = run_outer_calls(context)
        self.assertEqual(findings, [])

    def test_no_mutations_no_alert(self):
        context = _context_with_function(mutations=[])
        findings = run_outer_calls(context)
        self.assertEqual(findings, [])

    def test_finding_metadata_is_populated(self):
        context = _context_with_function()
        findings = run_outer_calls(context)
        self.assertEqual(findings[0].task_id, "11")
        self.assertEqual(findings[0].rule_id, "outer_calls")


if __name__ == "__main__":
    unittest.main()
