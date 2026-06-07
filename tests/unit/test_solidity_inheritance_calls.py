"""Tests for inheritance cross-type call edges and import resolution."""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.adapters.solidity.import_resolve import (
    collect_lines_with_imports,
    extract_local_sol_import_paths,
    resolve_import_path,
)
from smartgraphical.adapters.solidity.reader import ContractReader

CROSS_TYPE_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "fixtures",
    "solidity",
    "cross_type",
)
VALIDATOR_CHILD = os.path.join(CROSS_TYPE_DIR, "ValidatorChild.sol")
REWARD_BASE = os.path.join(CROSS_TYPE_DIR, "RewardBase.sol")


class TestImportResolve(unittest.TestCase):
    def test_extracts_relative_sol_paths(self):
        text = 'import {RewardBase} from "./RewardBase.sol";'
        paths = extract_local_sol_import_paths(text)
        self.assertIn("./RewardBase.sol", paths)

    def test_skips_at_prefixed_imports(self):
        text = 'import "@openzeppelin/contracts/token/ERC20.sol";'
        paths = extract_local_sol_import_paths(text)
        self.assertEqual(paths, [])

    def test_resolve_beside_file(self):
        resolved = resolve_import_path(VALIDATOR_CHILD, "./RewardBase.sol")
        self.assertEqual(os.path.abspath(resolved or ""), os.path.abspath(REWARD_BASE))

    def test_transitive_collect_includes_parent_contract(self):
        reader = ContractReader()
        lines = collect_lines_with_imports(VALIDATOR_CHILD, reader.read_file)
        blob = "".join(lines)
        self.assertIn("contract ValidatorChild", blob)
        self.assertIn("contract RewardBase", blob)


class TestInheritanceCrossTypeCalls(unittest.TestCase):
    def setUp(self):
        self.adapter = SolidityAdapterV0()

    def _cross_type_edges(self, context):
        return [
            e
            for e in context.normalized_model.call_edges
            if e.edge_kind == "cross_type_call"
            and (
                e.source_name == "approveValidators"
                or e.target_name == "approveValidators"
                or "_collateralize" in (e.source_name, e.target_name)
            )
        ]

    def test_single_file_resolves_parent_and_call_direction(self):
        context = self.adapter.parse_source(VALIDATOR_CHILD)
        type_names = {t.name for t in context.normalized_model.types}
        self.assertIn("ValidatorChild", type_names)
        self.assertIn("RewardBase", type_names)

        collateralize_edges = [
            e
            for e in self._cross_type_edges(context)
            if e.source_name == "approveValidators"
            and e.target_name == "_collateralize"
            and e.source_type == "ValidatorChild"
            and e.target_type == "RewardBase"
        ]
        self.assertEqual(
            len(collateralize_edges),
            1,
            "expected caller approveValidators -> callee _collateralize",
        )

    def test_no_reversed_collateralize_to_approve_edge(self):
        context = self.adapter.parse_source(VALIDATOR_CHILD)
        reversed_edges = [
            e
            for e in self._cross_type_edges(context)
            if e.source_name == "_collateralize"
            and e.target_name == "approveValidators"
        ]
        self.assertEqual(reversed_edges, [])

    def test_bundle_mode_does_not_inline_sibling_contracts(self):
        context = self.adapter.parse_source(
            VALIDATOR_CHILD,
            expand_local_imports=False,
        )
        type_names = [t.name for t in context.normalized_model.types]
        self.assertEqual(type_names, ["ValidatorChild"])
        self.assertNotIn("RewardBase", type_names)


if __name__ == "__main__":
    unittest.main()
