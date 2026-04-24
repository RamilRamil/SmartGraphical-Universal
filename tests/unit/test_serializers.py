"""Unit tests for smartgraphical.services.serializers."""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.core.findings import Finding, FindingEvidence
from smartgraphical.services.serializers import (
    evidence_to_dict,
    finding_to_dict,
    findings_to_list,
    model_graph_to_dict,
    model_summary_to_dict,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


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

    def test_model_summary_covers_core_counts(self):
        context = SolidityAdapterV0().parse_source(SIMPLE_AUCTION_PATH)
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
        context = SolidityAdapterV0().parse_source(SIMPLE_AUCTION_PATH)
        summary = model_summary_to_dict(context.normalized_model)
        graph = summary["graph"]
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreaterEqual(len(graph["nodes"]), 1)

    def test_model_graph_shape_is_cytoscape_ready(self):
        context = SolidityAdapterV0().parse_source(SIMPLE_AUCTION_PATH)
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

    def test_model_graph_handles_none(self):
        self.assertEqual(model_graph_to_dict(None), {"nodes": [], "edges": []})


if __name__ == "__main__":
    unittest.main()
