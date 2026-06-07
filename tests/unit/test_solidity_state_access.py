"""Unit and integration tests for Solidity state read/write classification."""
import unittest

from smartgraphical.adapters.solidity import state_access
from smartgraphical.adapters.solidity.adapter import build_normalized_model
from smartgraphical.adapters.solidity.reader import ContractReader
from smartgraphical.core.model import AnalysisContext, NormalizedArtifact, NormalizedAuditModel
from smartgraphical.services.serializers import model_graph_to_dict
from tests.support.solidity_context import analysis_context_stub, make_legacy_contract_ret


class TestStateAccessHelpers(unittest.TestCase):
    def test_comparison_is_not_write(self):
        stmt = "return rewards[vault].nonce != 0"
        self.assertFalse(
            state_access.statement_writes_to_var(stmt, "rewards", {}),
        )

    def test_local_load_is_not_write(self):
        stmt = "uint256 nonce = rewards[vault].nonce"
        self.assertTrue(state_access.is_local_load_from_storage(stmt, "rewards"))
        self.assertFalse(
            state_access.statement_writes_to_var(stmt, "rewards", {}),
        )

    def test_comment_prefix_stripped_from_statement(self):
        stmt = "// update state         lastReward.nonce = currentNonce"
        aliases = {"lastReward": "rewards"}
        self.assertTrue(
            state_access.statement_writes_to_var(stmt, "rewards", aliases),
        )
        self.assertNotIn("//", state_access._normalize_statement(stmt))

    def test_rewards_nonce_substring_not_matched(self):
        stmt = "return nonce != 0 && nonce + 1 < rewardsNonce"
        self.assertFalse(state_access.token_in_part(stmt, "rewards"))

    def test_direct_mapping_write(self):
        stmt = "rewards[vault] = Reward({nonce: rewardsNonce, assets: 0})"
        self.assertTrue(
            state_access.statement_writes_to_var(stmt, "rewards", {}),
        )

    def test_storage_alias_field_write(self):
        body = (
            "Reward storage lastReward = rewards[vault];"
            "lastReward.nonce = rewardsNonce;"
            "lastReward.assets = reward"
        )
        aliases = state_access.collect_storage_aliases(body, ["rewards"])
        self.assertEqual(aliases.get("lastReward"), "rewards")
        self.assertTrue(
            state_access.statement_writes_to_var(
                "lastReward.nonce = rewardsNonce",
                "rewards",
                aliases,
            ),
        )

    def test_view_pure_has_no_writes(self):
        body = (
            "uint256 nonce = rewards[vault].nonce;"
            "return nonce != 0 && nonce + 1 < rewardsNonce"
        )
        reads, writes, mutations = state_access.collect_function_state_accesses(
            body,
            ["rewards", "rewardsNonce"],
            ["view"],
        )
        self.assertTrue(any(a.entity_name == "rewards" for a in reads))
        self.assertFalse(any(a.entity_name == "rewards" for a in writes))
        self.assertEqual(mutations, [])

    def test_update_rewards_does_not_write_mapping_rewards(self):
        body = (
            "rewardsRoot = bytes32(uint256(1));"
            "rewardsNonce = rewardsNonce + 1"
        )
        _reads, writes, mutations = state_access.collect_function_state_accesses(
            body,
            ["rewards", "rewardsRoot", "rewardsNonce"],
            ["external"],
        )
        reward_writes = [w for w in writes if w.entity_name == "rewards"]
        self.assertEqual(reward_writes, [])
        self.assertTrue(any(w.entity_name == "rewardsRoot" for w in writes))


class TestCollateralStateFixtureIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reader = ContractReader()
        cls.fixture_path = "tests/fixtures/solidity/CollateralStateFixture.sol"

    def _build_model(self):
        lines = self.reader.read_file(self.fixture_path)
        unified = self.reader.unify_text(lines)
        rets, hierarchy, high_connections, unit_kinds = self.reader(unified)
        context = AnalysisContext(
            path=self.fixture_path,
            language="solidity",
            reader=self.reader,
            lines=lines,
            unified_code=unified,
            rets=rets,
            hierarchy=hierarchy,
            high_connections=high_connections,
            solidity_unit_kinds=unit_kinds,
        )
        return build_normalized_model(context)

    def _function(self, model, name):
        contract = model.types[0]
        for fn in contract.functions:
            if fn.name == name:
                return fn
        self.fail(f"function {name} not found")

    def test_view_functions_have_no_rewards_mutations(self):
        model = self._build_model()
        for fn_name in ("isCollateralized", "canHarvest", "isHarvestRequired"):
            fn = self._function(model, fn_name)
            reward_writes = [
                m for m in fn.mutations
                if state_access.token_in_part(m, "rewards")
            ]
            self.assertEqual(
                reward_writes,
                [],
                msg=f"{fn_name} should not mutate rewards",
            )

    def test_harvest_writes_rewards(self):
        model = self._build_model()
        fn = self._function(model, "harvest")
        self.assertTrue(
            any(
                state_access.token_in_part(m, "rewards") or "lastReward" in m
                for m in fn.mutations
            ),
        )

    def test_graph_read_write_edges(self):
        model = self._build_model()
        graph = model_graph_to_dict(model)
        kinds = {e["kind"] for e in graph["edges"]}
        self.assertIn("state_to_function_read", kinds)
        self.assertIn("state_to_function_write", kinds)
        self.assertNotIn("state_to_function", kinds)

    def test_graph_schema_version(self):
        model = self._build_model()
        graph = model_graph_to_dict(model)
        self.assertEqual(graph.get("graph_schema_version"), "1.1")


class TestRulesNoViewRewardsFalsePositive(unittest.TestCase):
    def test_view_reader_no_unallowed_manipulation_on_rewards(self):
        from smartgraphical.core.rules.solidity.state_mutation import (
            _unallowed_manipulation_from_normalized,
        )

        body = "return rewards[vault].nonce != 0"
        ret = make_legacy_contract_ret(
            "C",
            funcs=[
                [
                    "isCollateralized",
                    ["address vault"],
                    ["view", "public"],
                    body,
                ],
            ],
            vars_list=[["mapping(address => Reward)", "rewards"]],
        )
        model = build_normalized_model(
            analysis_context_stub(
                rets=[ret],
                path="x.sol",
            ),
        )
        alerts = _unallowed_manipulation_from_normalized(
            analysis_context_stub(normalized_model=model),
        )
        reward_alerts = [
            a for a in alerts
            if "rewards" in a.get("message", "").lower()
        ]
        self.assertEqual(reward_alerts, [])


if __name__ == "__main__":
    unittest.main()
