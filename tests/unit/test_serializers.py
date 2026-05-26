"""Unit tests for smartgraphical.services.serializers."""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.core.findings import Finding, FindingEvidence
from smartgraphical.services.serializers import (
    _is_graph_modifier_token,
    _state_entity_graph_extra,
    evidence_to_dict,
    finding_to_dict,
    findings_to_list,
    model_graph_to_dict,
    model_summary_to_dict,
)
from smartgraphical.core.model import (
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedCallEdge,
    NormalizedFunction,
    NormalizedStateEntity,
    NormalizedType,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")
# Optional repo-root golden contract used only for cytoscape graph shape assertions below.
SIMPLE_AUCTION_AT_ROOT = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class SerializerHelpersTests(unittest.TestCase):

    def test_evidence_to_dict_handles_none(self):
        self.assertIsNone(evidence_to_dict(None))

    def test_evidence_to_dict_preserves_fields(self):
        evidence = FindingEvidence(
            kind="statement",
            summary="example",
            type_name="Contract",
            function_name="fn",
            statement="x = 1;",
            source_statement="x = 1;",
            confidence_reason="pattern match",
        )
        serialized = evidence_to_dict(evidence)
        self.assertEqual(serialized["kind"], "statement")
        self.assertEqual(serialized["type_name"], "Contract")
        self.assertEqual(serialized["function_name"], "fn")

    def test_finding_to_dict_serializes_nested_evidences(self):
        evidence = FindingEvidence(kind="statement", summary="example")
        finding = Finding(
            task_id="11",
            legacy_code=11,
            rule_id="task-11",
            title="Outer calls",
            category="category",
            portability="portable",
            confidence="high",
            message="hello",
            remediation_hint="fix it",
            evidences=[evidence],
        )
        serialized = finding_to_dict(finding)
        self.assertEqual(serialized["task_id"], "11")
        self.assertEqual(serialized["legacy_code"], 11)
        self.assertEqual(len(serialized["evidences"]), 1)
        self.assertEqual(serialized["evidences"][0]["summary"], "example")

    def test_findings_to_list_returns_empty_for_none(self):
        self.assertEqual(findings_to_list(None), [])
        self.assertEqual(findings_to_list([]), [])

    def test_signature_annotations_are_not_graph_modifier_tokens(self):
        self.assertFalse(_is_graph_modifier_token("override(A, B)"))
        self.assertFalse(_is_graph_modifier_token("reinitializer(_version)"))
        self.assertTrue(_is_graph_modifier_token("nonReentrant"))
        self.assertTrue(_is_graph_modifier_token("onlyOwner"))

    def test_model_summary_covers_core_counts(self):
        if not os.path.isfile(SOL_FIXTURE):
            self.skipTest("solidity fixture MinimalGuard.sol missing")
        context = SolidityAdapterV0().parse_source(SOL_FIXTURE)
        summary = model_summary_to_dict(context.normalized_model)
        self.assertIn("types_count", summary)
        self.assertIn("functions_count", summary)
        self.assertIn("call_edges_count", summary)
        self.assertGreaterEqual(summary["types_count"], 1)
        self.assertIsNotNone(summary["artifact"])
        self.assertEqual(summary["artifact"]["language"], "solidity")

    def test_model_summary_tolerates_none(self):
        summary = model_summary_to_dict(None)
        self.assertEqual(summary["types_count"], 0)
        self.assertEqual(summary["functions_count"], 0)
        self.assertIsNone(summary["artifact"])
        self.assertEqual(summary["graph"], {"nodes": [], "edges": []})

    def test_model_summary_includes_graph(self):
        if not os.path.isfile(SOL_FIXTURE):
            self.skipTest("solidity fixture MinimalGuard.sol missing")
        context = SolidityAdapterV0().parse_source(SOL_FIXTURE)
        summary = model_summary_to_dict(context.normalized_model)
        graph = summary["graph"]
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreaterEqual(len(graph["nodes"]), 1)

    def test_model_graph_shape_is_cytoscape_ready(self):
        if not os.path.isfile(SIMPLE_AUCTION_AT_ROOT):
            self.skipTest(
                "SimpleAuction.sol not at repo root (optional golden for graph-shape test)"
            )
        context = SolidityAdapterV0().parse_source(SIMPLE_AUCTION_AT_ROOT)
        graph = model_graph_to_dict(context.normalized_model)
        type_nodes = [node for node in graph["nodes"] if node["group"] == "type"]
        function_nodes = [
            node for node in graph["nodes"] if node["group"] == "function"
        ]
        event_nodes = [node for node in graph["nodes"] if node["group"] == "event"]
        modifier_nodes = [node for node in graph["nodes"] if node["group"] == "modifier"]
        self.assertGreaterEqual(len(type_nodes), 1)
        self.assertGreaterEqual(len(function_nodes), 1)
        self.assertTrue(any(node["label"] == "BidPlaced" for node in event_nodes))
        self.assertTrue(any(node["label"] == "AuctionEnded" for node in event_nodes))
        self.assertTrue(any(node["label"] == "onlyOwner" for node in modifier_nodes))
        for node in function_nodes:
            self.assertTrue(node["parent"].startswith("type:"))
            self.assertIn("visibility", node)
            self.assertIn("is_entrypoint", node)
            self.assertIn("source_body", node)
            self.assertIn("calls_internal", node)
            self.assertIn("calls_event", node)
            self.assertIn("calls_custom_error", node)
        end_auction = next(
            n for n in function_nodes if n["label"] == "endAuction"
        )
        self.assertIn("emit AuctionEnded", end_auction["source_body"])
        self.assertIn("modifier_ring_details", end_auction)
        self.assertEqual(end_auction["modifier_ring_details"][0]["name"], "onlyOwner")
        self.assertEqual(end_auction["modifier_ring_details"][0]["color"], "#22c55e")
        self.assertTrue(end_auction.get("modifier_details"))
        emit_edges = [
            e for e in graph["edges"] if e["kind"] == "function_to_event"
        ]
        self.assertGreaterEqual(len(emit_edges), 2)
        bid_fn_id = next(n["id"] for n in function_nodes if n["label"] == "bid")
        bid_emits = [
            e for e in emit_edges
            if e["source"] == bid_fn_id and e["target"].startswith("event:")
        ]
        self.assertEqual(len(bid_emits), 1)
        only_owner_targets = [
            e for e in graph["edges"] if e["target"].endswith(".onlyOwner")
        ]
        self.assertTrue(
            all(target["target"].startswith("modifier:") for target in only_owner_targets)
        )
        self.assertFalse(
            any(node["id"] == "external:onlyOwner" for node in graph["nodes"])
        )
        node_ids = {node["id"] for node in graph["nodes"]}
        for edge in graph["edges"]:
            self.assertIn(edge["source"], node_ids)
            self.assertIn(edge["target"], node_ids)
            self.assertIn("kind", edge)

    def test_model_graph_includes_solidity_custom_errors(self):
        import tempfile
        src = (
            "pragma solidity ^0.8.0;\n"
            "contract C {\n"
            "    error BadThing();\n"
            "    function f() external { revert BadThing(); }\n"
            "}\n"
        )
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False, encoding="utf-8")
        try:
            tmp.write(src)
            tmp.close()
            ctx = SolidityAdapterV0().parse_source(tmp.name)
            graph = model_graph_to_dict(ctx.normalized_model)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        err_nodes = [n for n in graph["nodes"] if n["group"] == "custom_error"]
        self.assertTrue(any(n["label"] == "BadThing" for n in err_nodes))
        rev = [e for e in graph["edges"] if e["kind"] == "function_to_custom_error"]
        self.assertGreaterEqual(len(rev), 1)
        fn_f = next(n for n in graph["nodes"] if n["group"] == "function" and n["label"] == "f")
        self.assertTrue(fn_f.get("calls_custom_error"))

    def test_state_entity_graph_extra_parses_solidity_declaration(self):
        entity = NormalizedStateEntity(
            name="amount",
            owner="MinimalGuard",
            kind="state_variable",
            raw_signature="uint256 public amount",
        )
        extra = _state_entity_graph_extra(entity)
        self.assertEqual(extra["variable_type"], "uint256")
        self.assertEqual(extra["visibility"], "public")

    def test_model_graph_state_variable_has_type_and_usage(self):
        entity = NormalizedStateEntity(
            name="amount",
            owner="C",
            kind="state_variable",
            raw_signature="uint256 public amount",
        )
        fn = NormalizedFunction(name="setAmount", owner="C", visibility="external")
        type_entry = NormalizedType(
            name="C",
            kind="contract_like",
            functions=[fn],
            state_entities=[entity],
        )
        model = NormalizedAuditModel(
            artifact=NormalizedArtifact(
                path="x.sol", language="solidity", adapter_name="test",
            ),
            types=[type_entry],
            call_edges=[
                NormalizedCallEdge("C", "amount", "C", "setAmount", "state_to_function_write"),
            ],
        )
        graph = model_graph_to_dict(model)
        amount = next(
            n for n in graph["nodes"] if n["group"] == "state" and n["label"] == "amount"
        )
        self.assertEqual(amount["kind"], "state_variable")
        self.assertEqual(amount["variable_type"], "uint256")
        self.assertEqual(amount["visibility"], "public")
        self.assertIn("uint256 public amount", amount["source_body"])
        fn_ids = {
            e["target"]
            for e in graph["edges"]
            if e["kind"] == "state_to_function_write" and e["source"] == amount["id"]
        }
        self.assertTrue(
            any(
                n["id"] in fn_ids and n["label"] == "setAmount"
                for n in graph["nodes"]
                if n["group"] == "function"
            )
        )

    def test_model_graph_handles_none(self):
        self.assertEqual(
            model_graph_to_dict(None),
            {"graph_schema_version": "1.1", "nodes": [], "edges": []},
        )


if __name__ == "__main__":
    unittest.main()
