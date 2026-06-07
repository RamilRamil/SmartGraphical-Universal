"""State variable extraction: sized integers, mapping, custom types."""
import os
import tempfile
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0
from smartgraphical.services.serializers import model_graph_to_dict


def _state_names(model, type_name):
    for t in model.types:
        if t.name == type_name:
            return {
                e.name
                for e in t.state_entities
                if e.kind == "state_variable"
            }
    return set()


class MinimalStateVariableTests(unittest.TestCase):
    _SRC = (
        "pragma solidity ^0.8.22;\n"
        "library QueueHistoryLib {\n"
        "    struct History { uint256 x; }\n"
        "}\n"
        "abstract contract MultiStateFields {\n"
        "    uint256 internal _donatedAssets;\n"
        "    uint128 internal _totalShares;\n"
        "    mapping(address => uint256) internal _balances;\n"
        "    QueueHistoryLib.History internal _exitQueue;\n"
        "}\n"
    )

    def _parse(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False, encoding="utf-8")
        try:
            tmp.write(self._SRC)
            tmp.close()
            return SolidityAdapterV0().parse_source(tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def test_sized_uint_and_custom_type_state_entities(self):
        ctx = self._parse()
        names = _state_names(ctx.normalized_model, "MultiStateFields")
        for expected in (
            "_donatedAssets",
            "_totalShares",
            "_balances",
            "_exitQueue",
        ):
            self.assertIn(expected, names, f"missing {expected} in {sorted(names)}")


class MultiStateFieldsFixtureTests(unittest.TestCase):
    _PATH = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "fixtures", "solidity", "MultiStateFields.sol"),
    )

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(cls._PATH):
            raise unittest.SkipTest(f"missing {cls._PATH}")
        cls.ctx = SolidityAdapterV0().parse_source(cls._PATH, expand_local_imports=False)

    def test_multi_state_fixture_includes_donated_assets_and_mappings(self):
        names = _state_names(self.ctx.normalized_model, "MultiStateFields")
        for expected in (
            "_donatedAssets",
            "_exitRequests",
            "_balances",
            "_totalShares",
            "_exitQueue",
            "_capacity",
        ):
            self.assertIn(expected, names, f"missing {expected}; got {sorted(names)}")
        self.assertGreaterEqual(len(names), 10)

    def test_graph_state_nodes_match_model(self):
        graph = model_graph_to_dict(self.ctx.normalized_model)
        labels = {
            n["label"]
            for n in graph.get("nodes") or []
            if n.get("group") == "state"
            and n.get("type_name") == "MultiStateFields"
        }
        self.assertIn("_donatedAssets", labels)


if __name__ == "__main__":
    unittest.main()
