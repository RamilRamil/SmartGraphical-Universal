"""Regression: Solidity unit kinds (concrete / abstract / interface / library) on model and graph."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SolidityAbstractContractTests(unittest.TestCase):
    def test_examples_erc20_upgradeable_is_abstract_in_context_and_model(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0

        path = str(ROOT / "examples" / "ERC20Upgradeable.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        self.assertEqual(ctx.solidity_unit_kinds.get("ERC20Upgradeable"), "abstract")
        self.assertTrue(ctx.normalized_model.types)
        t0 = ctx.normalized_model.types[0]
        self.assertEqual(t0.name, "ERC20Upgradeable")
        self.assertTrue(t0.is_abstract)
        self.assertEqual(t0.solidity_unit_kind, "abstract")

    def test_minimal_guard_concrete_not_abstract(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0

        path = str(ROOT / "tests" / "fixtures" / "solidity" / "MinimalGuard.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        self.assertEqual(ctx.solidity_unit_kinds.get("MinimalGuard"), "concrete")
        self.assertTrue(ctx.normalized_model.types)
        self.assertFalse(ctx.normalized_model.types[0].is_abstract)
        self.assertEqual(ctx.normalized_model.types[0].solidity_unit_kind, "concrete")

    def test_graph_payload_marks_abstract_type_node(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
        from smartgraphical.services.serializers import model_graph_to_dict

        path = str(ROOT / "examples" / "ERC20Upgradeable.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        graph = model_graph_to_dict(ctx.normalized_model)
        type_nodes = [n for n in graph["nodes"] if n.get("group") == "type"]
        self.assertTrue(type_nodes)
        erc = next(n for n in type_nodes if n.get("label") == "ERC20Upgradeable")
        self.assertEqual(erc.get("solidity_kind"), "abstract")

    def test_graph_omits_solidity_kind_for_concrete_contract(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
        from smartgraphical.services.serializers import model_graph_to_dict

        path = str(ROOT / "tests" / "fixtures" / "solidity" / "MinimalGuard.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        graph = model_graph_to_dict(ctx.normalized_model)
        type_nodes = [n for n in graph["nodes"] if n.get("group") == "type"]
        self.assertTrue(type_nodes)
        self.assertNotIn("solidity_kind", type_nodes[0])

    def test_interface_fixture_kind_and_graph(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
        from smartgraphical.services.serializers import model_graph_to_dict

        path = str(ROOT / "tests" / "fixtures" / "solidity" / "SampleInterface.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        self.assertEqual(ctx.solidity_unit_kinds.get("ISample"), "interface")
        graph = model_graph_to_dict(ctx.normalized_model)
        type_nodes = [n for n in graph["nodes"] if n.get("group") == "type"]
        iface = next(n for n in type_nodes if n.get("label") == "ISample")
        self.assertEqual(iface.get("solidity_kind"), "interface")

    def test_library_fixture_kind_and_graph(self):
        from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
        from smartgraphical.services.serializers import model_graph_to_dict

        path = str(ROOT / "tests" / "fixtures" / "solidity" / "SampleLibrary.sol")
        ctx = SolidityAdapterV0().parse_source(path)
        self.assertEqual(ctx.solidity_unit_kinds.get("SampleLib"), "library")
        graph = model_graph_to_dict(ctx.normalized_model)
        type_nodes = [n for n in graph["nodes"] if n.get("group") == "type"]
        lib = next(n for n in type_nodes if n.get("label") == "SampleLib")
        self.assertEqual(lib.get("solidity_kind"), "library")


if __name__ == "__main__":
    unittest.main()
