"""Tests for engine._infer_evidence: evidence inference from messages + model."""
import unittest

from smartgraphical.core.engine import _infer_evidence
from smartgraphical.core.model import (
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)


def _make_model_with_function(type_name, function_name, evidence_index=None):
    artifact = NormalizedArtifact(path="x.sol", language="solidity", adapter_name="Test")
    model = NormalizedAuditModel(artifact=artifact)
    type_entry = NormalizedType(name=type_name, kind="contract_like")
    type_entry.functions.append(NormalizedFunction(name=function_name, owner=type_name))
    model.types.append(type_entry)
    if evidence_index is not None:
        model.findings_data.evidence_index.update(evidence_index)
    return model


class InferEvidenceTests(unittest.TestCase):

    def test_falls_back_to_message_only_when_no_match(self):
        model = _make_model_with_function("AlphaType", "alphaFunction")
        evidence = _infer_evidence("completely unrelated text", model)
        self.assertEqual(evidence.kind, "message")
        self.assertEqual(evidence.summary, "completely unrelated text")
        self.assertEqual(evidence.confidence_reason, "message_only_fallback")
        self.assertEqual(evidence.type_name, "")
        self.assertEqual(evidence.function_name, "")

    def test_matches_type_name_when_message_mentions_it(self):
        model = _make_model_with_function("MarketType", "otherFunction")
        evidence = _infer_evidence("something about MarketType happened", model)
        self.assertEqual(evidence.type_name, "MarketType")

    def test_matches_function_name_and_sets_reason(self):
        model = _make_model_with_function("TypeOne", "transfer")
        evidence = _infer_evidence("found issue in transfer here", model)
        self.assertEqual(evidence.function_name, "transfer")
        self.assertEqual(evidence.type_name, "TypeOne")
        self.assertEqual(evidence.confidence_reason, "matched_function_name")

    def test_matches_qualified_function_name(self):
        model = _make_model_with_function(
            "MarketType", "swap",
            evidence_index={"MarketType.swap": []},
        )
        evidence = _infer_evidence(
            "issue in MarketType.swap path",
            model,
        )
        self.assertEqual(evidence.type_name, "MarketType")
        self.assertEqual(evidence.function_name, "swap")
        self.assertEqual(evidence.confidence_reason, "matched_qualified_function_name")

    def test_matches_statement_from_evidence_index_wins(self):
        evidence_index = {
            "Pool.mintTokens": [
                {
                    "type_name": "Pool",
                    "function_name": "mintTokens",
                    "source_statement": "balance = amount",
                    "confidence_reason": "mutation_detected_from_state_assignment",
                },
            ],
        }
        model = _make_model_with_function("Pool", "mintTokens", evidence_index=evidence_index)
        message = "Some text that includes balance = amount inside it"
        evidence = _infer_evidence(message, model)

        self.assertEqual(evidence.type_name, "Pool")
        self.assertEqual(evidence.function_name, "mintTokens")
        self.assertEqual(evidence.source_statement, "balance = amount")
        self.assertEqual(evidence.statement, "balance = amount")
        self.assertEqual(
            evidence.confidence_reason,
            "mutation_detected_from_state_assignment",
        )

    def test_statement_extracted_from_line_marker(self):
        model = _make_model_with_function("TypeA", "f")
        evidence = _infer_evidence(
            "something happened, line: balance = x",
            model,
        )
        self.assertEqual(evidence.statement, "balance = x")
        self.assertEqual(evidence.source_statement, "balance = x")

    def test_statement_extracted_from_last_quoted_part_when_no_line(self):
        model = _make_model_with_function("TypeA", "otherFunc")
        evidence = _infer_evidence(
            "problem in 'TypeA' with 'suspiciousVar'",
            model,
        )
        self.assertEqual(evidence.statement, "suspiciousVar")


if __name__ == "__main__":
    unittest.main()
