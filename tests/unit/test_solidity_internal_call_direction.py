"""Regression tests for Solidity function_to_function edge direction (caller -> callee)."""
import os
import tempfile
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.services.serializers import model_graph_to_dict


def _internal_edges(model, source_name=None, target_name=None):
    edges = [
        e
        for e in model.call_edges
        if e.edge_kind == "function_to_function"
    ]
    if source_name is not None:
        edges = [e for e in edges if e.source_name == source_name]
    if target_name is not None:
        edges = [e for e in edges if e.target_name == target_name]
    return edges


def _graph_internal_edges(graph, source_label=None, target_label=None):
    by_id = {n["id"]: n for n in graph.get("nodes") or []}

    def _label(node_id):
        node = by_id.get(node_id) or {}
        return str(node.get("label", ""))

    edges = [
        e for e in graph.get("edges") or []
        if e.get("kind") == "function_to_function"
    ]
    if source_label is not None:
        edges = [e for e in edges if _label(e.get("source", "")) == source_label]
    if target_label is not None:
        edges = [e for e in edges if _label(e.get("target", "")) == target_label]
    return edges


class SolidityInternalCallDirectionTests(unittest.TestCase):
    _MINIMAL_SRC = (
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function deposit(address receiver) public {\n"
        "        receiver;\n"
        "    }\n"
        "    function updateStateAndDeposit(address receiver) public {\n"
        "        updateState();\n"
        "        deposit(receiver);\n"
        "    }\n"
        "    function updateState() internal {}\n"
        "}\n"
    )

    def _parse_minimal(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False, encoding="utf-8")
        try:
            tmp.write(self._MINIMAL_SRC)
            tmp.close()
            return SolidityAdapterV0().parse_source(tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def test_caller_to_callee_on_normalized_model(self):
        ctx = self._parse_minimal()
        forward = _internal_edges(
            ctx.normalized_model,
            source_name="updateStateAndDeposit",
            target_name="deposit",
        )
        self.assertEqual(len(forward), 1, "expected caller -> callee edge")
        reversed_edges = _internal_edges(
            ctx.normalized_model,
            source_name="deposit",
            target_name="updateStateAndDeposit",
        )
        self.assertEqual(reversed_edges, [])

    def test_caller_to_callee_on_serialized_graph(self):
        ctx = self._parse_minimal()
        graph = model_graph_to_dict(ctx.normalized_model)
        forward = _graph_internal_edges(
            graph,
            source_label="updateStateAndDeposit",
            target_label="deposit",
        )
        self.assertEqual(len(forward), 1)
        reversed_edges = _graph_internal_edges(
            graph,
            source_label="deposit",
            target_label="updateStateAndDeposit",
        )
        self.assertEqual(reversed_edges, [])

    def test_calls_internal_flag_on_caller(self):
        ctx = self._parse_minimal()
        graph = model_graph_to_dict(ctx.normalized_model)
        nodes = {n["label"]: n for n in graph.get("nodes") or [] if n.get("group") == "function"}
        caller = nodes.get("updateStateAndDeposit") or {}
        callee = nodes.get("deposit") or {}
        self.assertTrue(caller.get("calls_internal"))
        self.assertFalse(callee.get("calls_internal"))


class EthMetaVaultInternalCallDirectionTests(unittest.TestCase):
    _EXAMPLE = os.path.join(
        os.path.dirname(__file__),
        "..",
        "fixtures",
        "solidity",
        "EthMetaVault.sol",
    )

    @classmethod
    def setUpClass(cls):
        cls._example_path = os.path.normpath(cls._EXAMPLE)
        if not os.path.isfile(cls._example_path):
            raise unittest.SkipTest(f"missing fixture {cls._example_path}")
        adapter = SolidityAdapterV0()
        ctx = adapter.parse_source(cls._example_path, expand_local_imports=False)
        cls.graph = model_graph_to_dict(ctx.normalized_model)

    def test_update_state_and_deposit_calls_deposit(self):
        forward = _graph_internal_edges(
            self.graph,
            source_label="updateStateAndDeposit",
            target_label="deposit",
        )
        self.assertGreaterEqual(
            len(forward),
            1,
            "expected updateStateAndDeposit -> deposit",
        )
        reversed_edges = _graph_internal_edges(
            self.graph,
            source_label="deposit",
            target_label="updateStateAndDeposit",
        )
        self.assertEqual(reversed_edges, [])


if __name__ == "__main__":
    unittest.main()
