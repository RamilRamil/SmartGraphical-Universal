"""Model shape tests: fix the structural contract of the normalized model.

These tests do not depend on the adapter or any rule logic. They protect the
core dataclasses, their default factories, and the fact that different model
sections do not share mutable state.
"""
import unittest

from smartgraphical.core.findings import Finding, FindingEvidence
from smartgraphical.core.model import (
    AdapterBlueprint,
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedEvent,
    NormalizedExplorationData,
    NormalizedExternalCall,
    NormalizedFindingsData,
    NormalizedFunction,
    NormalizedGuardFact,
    NormalizedObjectUse,
    NormalizedStateAccess,
    NormalizedStateEntity,
    NormalizedType,
)


def _make_model():
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="TestAdapter")
    return NormalizedAuditModel(artifact=artifact)


class NormalizedFunctionShapeTests(unittest.TestCase):

    def test_default_factories_are_independent_lists(self):
        function_a = NormalizedFunction(name="a", owner="T")
        function_b = NormalizedFunction(name="b", owner="T")

        function_a.guard_facts.append(NormalizedGuardFact("require", "x>0"))
        function_a.mutations.append("balance = 1")
        function_a.exploration_statements.append("stmt1")
        function_a.findings_evidence_map.append({"key": "value"})

        self.assertEqual(function_b.guard_facts, [])
        self.assertEqual(function_b.mutations, [])
        self.assertEqual(function_b.exploration_statements, [])
        self.assertEqual(function_b.findings_evidence_map, [])

    def test_required_fields_are_present(self):
        function = NormalizedFunction(name="f", owner="C")

        expected_fields = {
            "name", "owner", "inputs", "modifiers", "body", "conditionals",
            "guards", "guard_facts", "internal_calls", "system_calls",
            "object_calls", "mutations", "read_accesses", "transfers",
            "external_calls", "computations", "is_entrypoint", "visibility",
            "entrypoint_permissions", "findings_evidence_map",
            "exploration_statements",
        }
        for field_name in expected_fields:
            self.assertTrue(
                hasattr(function, field_name),
                msg=f"NormalizedFunction must expose '{field_name}'",
            )

    def test_visibility_defaults_to_empty_string(self):
        function = NormalizedFunction(name="f", owner="C")
        self.assertEqual(function.visibility, "")
        self.assertFalse(function.is_entrypoint)


class NormalizedAuditModelShapeTests(unittest.TestCase):

    def test_exploration_and_findings_are_independent(self):
        model_a = _make_model()
        model_b = _make_model()

        model_a.exploration_data.function_notes["C.f"] = {"statement_count": 3}
        model_a.findings_data.evidence_index["C.f"] = [{"source_statement": "x"}]

        self.assertEqual(model_b.exploration_data.function_notes, {})
        self.assertEqual(model_b.findings_data.evidence_index, {})

    def test_findings_and_exploration_are_separate_containers(self):
        model = _make_model()
        self.assertIsInstance(model.exploration_data, NormalizedExplorationData)
        self.assertIsInstance(model.findings_data, NormalizedFindingsData)
        self.assertIsNot(model.exploration_data.function_notes, model.findings_data.function_facts)
        self.assertIsNot(model.exploration_data.function_notes, model.findings_data.evidence_index)

    def test_types_list_is_isolated_per_instance(self):
        model_a = _make_model()
        model_b = _make_model()
        model_a.types.append(NormalizedType(name="A", kind="contract_like"))
        self.assertEqual(model_b.types, [])

    def test_call_edges_and_rule_groups_defaults(self):
        model = _make_model()
        self.assertEqual(model.call_edges, [])
        self.assertEqual(model.rule_groups, {})
        self.assertIsNone(model.second_language_poc)


class SupportingDataclassesTests(unittest.TestCase):

    def test_guard_fact_defaults(self):
        fact = NormalizedGuardFact(guard_type="require", expression="x > 0")
        self.assertEqual(fact.source_statement, "")
        self.assertEqual(fact.confidence_reason, "")

    def test_state_access_defaults(self):
        access = NormalizedStateAccess(entity_name="balance", access_kind="read")
        self.assertEqual(access.source_statement, "")

    def test_external_call_defaults(self):
        call = NormalizedExternalCall(call_kind="value_or_low_level", target_name="unknown")
        self.assertEqual(call.source_statement, "")
        self.assertEqual(call.via_object, "")

    def test_call_edge_label_defaults_to_empty(self):
        edge = NormalizedCallEdge(
            source_type="A", source_name="a", target_type="B",
            target_name="b", edge_kind="function_to_function",
        )
        self.assertEqual(edge.label, "")

    def test_event_and_object_defaults(self):
        event = NormalizedEvent(name="Transfer", owner="C")
        self.assertEqual(event.inputs, [])
        obj = NormalizedObjectUse(object_name="token", contract_name="C")
        self.assertEqual(obj.label, "")

    def test_state_entity_raw_signature_defaults(self):
        entity = NormalizedStateEntity(name="x", owner="C", kind="state_variable")
        self.assertEqual(entity.raw_signature, "")

    def test_adapter_blueprint_defaults(self):
        blueprint = AdapterBlueprint(target_language="rust_or_cpp")
        self.assertEqual(blueprint.required_entities, [])
        self.assertEqual(blueprint.portable_rule_tasks, [])
        self.assertEqual(blueprint.success_criteria, [])

    def test_analysis_context_normalized_model_defaults_to_none(self):
        context = AnalysisContext(
            path="x.sol", language="solidity", reader=None, lines=[],
            unified_code="", rets=[], hierarchy={}, high_connections=[],
        )
        self.assertIsNone(context.normalized_model)


class FindingDataclassesTests(unittest.TestCase):

    def test_finding_evidence_exposes_phase3_fields(self):
        evidence = FindingEvidence(kind="statement", summary="example")
        self.assertEqual(evidence.type_name, "")
        self.assertEqual(evidence.function_name, "")
        self.assertEqual(evidence.statement, "")
        self.assertEqual(evidence.source_statement, "")
        self.assertEqual(evidence.confidence_reason, "")

    def test_finding_evidences_default_isolated(self):
        finding_a = Finding(
            task_id="1", legacy_code=1, rule_id="slug", title="t",
            category="c", portability="p", confidence="c",
            message="m", remediation_hint="h",
        )
        finding_b = Finding(
            task_id="1", legacy_code=1, rule_id="slug", title="t",
            category="c", portability="p", confidence="c",
            message="m", remediation_hint="h",
        )
        finding_a.evidences.append(FindingEvidence(kind="message", summary="x"))
        self.assertEqual(finding_b.evidences, [])


if __name__ == "__main__":
    unittest.main()
