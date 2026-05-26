"""Graph regressions for import wiring and modifier parsing (EthMetaVault)."""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.services.serializers import model_graph_to_dict


class EthMetaVaultImportModifierGraphTests(unittest.TestCase):
    _EXAMPLE = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "examples",
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

    def test_no_phantom_external_eth_meta_vault_node(self):
        nodes = self.graph.get("nodes") or []
        for node in nodes:
            node_id = str(node.get("id", ""))
            group = str(node.get("group", ""))
            label = str(node.get("label", ""))
            if label == "EthMetaVault" and group == "external":
                self.fail(f"unexpected external stub node: {node_id}")
            if node_id == "external:EthMetaVault":
                self.fail("contract-level imports must not spawn external:EthMetaVault")

    def test_unused_import_edges_origin_from_type_node(self):
        edges = self.graph.get("edges") or []
        type_id = "type:EthMetaVault"
        for edge in edges:
            if edge.get("kind") != "import_dependency":
                continue
            if edge.get("source") != type_id:
                continue
            self.assertEqual(edge.get("source"), type_id)
            return
        self.fail("expected at least one import_dependency edge from type:EthMetaVault")

    def test_no_split_override_modifier_nodes(self):
        nodes = self.graph.get("nodes") or []
        for node in nodes:
            if node.get("group") != "modifier":
                continue
            label = str(node.get("label", ""))
            if label.startswith("override(") or label.startswith("reinitializer("):
                self.fail(f"signature annotation must not be modifier node: {label!r}")
            if label.endswith(")") and not label.startswith("override("):
                self.fail(f"orphan override tail modifier node: {label!r}")
            if label in {"internal", "external", "public", "virtual", "override", "view", "pure"}:
                self.fail(f"signature keyword promoted to modifier node: {label!r}")


if __name__ == "__main__":
    unittest.main()
