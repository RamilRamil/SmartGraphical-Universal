"""Model-level coverage for Solidity rules not covered by sibling test modules.

See docs/testing_practices_implementation_plan.md (phase 1).
"""
import unittest

from smartgraphical.core.model import NormalizedFunction, NormalizedGuardFact, NormalizedStateEntity
from smartgraphical.core.rules.access_control import run as run_local_points
from smartgraphical.core.rules.computation import run as run_complicated_calculations
from smartgraphical.core.rules.error_handling import run as run_exceptions
from smartgraphical.core.rules.naming import run_contract_version, run_similar_names
from smartgraphical.core.rules.staking import run as run_staking
from smartgraphical.core.rules.state_mutation import run_pool_interactions as run_pool_interactions
from smartgraphical.core.rules.withdraw import run as run_withdraw_check
from tests.support.solidity_context import (
    TextLineSepReader,
    analysis_context_stub,
    make_legacy_contract_ret,
    minimal_audit_model,
)


class ContractVersionRuleTests(unittest.TestCase):
    def test_comment_with_version_keyword_triggers(self):
        model = minimal_audit_model()
        ctx = analysis_context_stub(
            normalized_model=model,
            lines=["// planning a version upgrade here\n"],
            reader=TextLineSepReader(),
        )
        findings = run_contract_version(ctx)
        self.assertTrue(findings, msg="expected a finding for version keyword in comment")
        self.assertEqual(findings[0].rule_id, "contract_version")
        self.assertEqual(findings[0].task_id, "1")

    def test_no_comment_lines_skips(self):
        model = minimal_audit_model()
        ctx = analysis_context_stub(
            normalized_model=model,
            lines=["contract C { uint x; }\n"],
            reader=TextLineSepReader(),
        )
        findings = run_contract_version(ctx)
        self.assertEqual(findings, [])


class SimilarNamesRuleTests(unittest.TestCase):
    def test_near_duplicate_function_names_triggers(self):
        model = minimal_audit_model("C")
        funcs = [
            ["depositToken", [["uint256"], ["amt"]], ["external"], "{}"],
            ["depositTokn", [["uint256"], ["amt"]], ["external"], "{}"],
        ]
        ret = make_legacy_contract_ret("C", funcs=funcs)
        ctx = analysis_context_stub(normalized_model=model, rets=[ret])
        findings = run_similar_names(ctx)
        self.assertTrue(any(f.rule_id == "similar_names" for f in findings))
        self.assertTrue(any("similar function names" in f.message for f in findings))
        meta = next(f for f in findings if f.rule_id == "similar_names")
        self.assertEqual(meta.task_id, "10")

    def test_dissimilar_function_names_negative(self):
        model = minimal_audit_model("C")
        funcs = [
            ["deposit", [["uint256"], ["a"]], ["external"], "{}"],
            ["withdraw", [["uint256"], ["a"]], ["external"], "{}"],
        ]
        ret = make_legacy_contract_ret("C", funcs=funcs)
        ctx = analysis_context_stub(normalized_model=model, rets=[ret])
        findings = run_similar_names(ctx)
        similar = [f for f in findings if f.rule_id == "similar_names"]
        self.assertEqual(similar, [])


class StakingRuleTests(unittest.TestCase):
    def test_stake_without_unstake_triggers_symmetry_alert(self):
        model = minimal_audit_model("Vault")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="stakeFunds",
                owner="Vault",
                visibility="external",
                is_entrypoint=True,
                inputs=[["uint256"], ["amt"]],
                mutations=["stakes[msg.sender] += amt"],
                exploration_statements=["stakes[msg.sender] += amt"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_staking(ctx)
        self.assertTrue(any("No unstake function" in f.message for f in findings))
        meta = next(f for f in findings if f.rule_id == "staking")
        self.assertEqual(meta.task_id, "3")

    def test_no_stake_semantics_negative(self):
        model = minimal_audit_model("Vault")
        model.types[0].functions.append(
            NormalizedFunction(
                name="deposit_eth",
                owner="Vault",
                visibility="external",
                is_entrypoint=True,
                inputs=[["uint256"], ["amt"]],
                mutations=["balances[msg.sender] += amt"],
                exploration_statements=["balances[msg.sender] += amt"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_staking(ctx)
        self.assertEqual(findings, [])


class WithdrawRuleTests(unittest.TestCase):
    def test_transfer_without_guards_triggers(self):
        model = minimal_audit_model("W")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="pay",
                owner="W",
                transfers=["payable(recipient).transfer(amount)"],
                exploration_statements=["payable(recipient).transfer(amount)"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_withdraw_check(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "withdraw_check")
        self.assertIn("no explicit guards", findings[0].message)

    def test_transfer_with_guard_facts_negative(self):
        model = minimal_audit_model("W")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="pay",
                owner="W",
                guard_facts=[
                    NormalizedGuardFact(guard_type="require", expression="amount > 0"),
                ],
                transfers=["payable(recipient).transfer(amount)"],
                exploration_statements=["payable(recipient).transfer(amount)"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_withdraw_check(ctx)
        self.assertEqual(findings, [])


class ComputationRuleTests(unittest.TestCase):
    def test_mul_div_statement_triggers_division_related_findings(self):
        model = minimal_audit_model("M")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="f",
                owner="M",
                computations=["uint256 x = a * b / c"],
                exploration_statements=["uint256 x = a * b / c"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_complicated_calculations(ctx)
        msgs = [f.message for f in findings]
        self.assertTrue(any("Multiplication and division" in m for m in msgs))
        self.assertTrue(any("Division is occured" in m for m in msgs))
        self.assertEqual(findings[0].rule_id, "complicated_calculations")
        self.assertEqual(findings[0].task_id, "7")

    def test_no_computation_list_negative(self):
        model = minimal_audit_model("M")
        model.types[0].functions.append(
            NormalizedFunction(name="g", owner="M", computations=[]),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_complicated_calculations(ctx)
        self.assertEqual(findings, [])


class ExceptionsRuleTests(unittest.TestCase):
    def test_revert_in_catch_triggers(self):
        model = minimal_audit_model("E")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="f",
                owner="E",
                body="try { foo(); } catch { revert(\"e\"); }",
                exploration_statements=['revert(\"e\")'],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_exceptions(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "exceptions")
        self.assertEqual(findings[0].task_id, "6")
        self.assertIn("Revert action found", findings[0].message)

    def test_no_try_catch_negative(self):
        model = minimal_audit_model("E")
        model.types[0].functions.append(
            NormalizedFunction(name="g", owner="E", body="return 1;", exploration_statements=["return 1"]),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_exceptions(ctx)
        self.assertEqual(findings, [])


class LocalPointsRuleTests(unittest.TestCase):
    def test_take_without_balance_guard_triggers_when_balance_declared(self):
        model = minimal_audit_model("P")
        t = model.types[0]
        t.state_entities.append(NormalizedStateEntity("balance", "P", "uint256", ""))
        t.functions.append(
            NormalizedFunction(
                name="takeFee",
                owner="P",
                mutations=["msg.sender += 1"],
                exploration_statements=["msg.sender += 1"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_local_points(ctx)
        self.assertTrue(findings)
        self.assertEqual(findings[0].rule_id, "local_points")
        self.assertEqual(findings[0].task_id, "5")

    def test_take_with_balance_in_require_negative(self):
        model = minimal_audit_model("P")
        t = model.types[0]
        t.state_entities.append(NormalizedStateEntity("balance", "P", "uint256", ""))
        t.functions.append(
            NormalizedFunction(
                name="takeFee",
                owner="P",
                guard_facts=[
                    NormalizedGuardFact(guard_type="require", expression="balances[msg.sender] > 0"),
                ],
                exploration_statements=["return"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_local_points(ctx)
        self.assertEqual(findings, [])


class PoolInteractionsRuleTests(unittest.TestCase):
    def test_external_mint_without_modifier_triggers(self):
        model = minimal_audit_model("T")
        t = model.types[0]
        t.functions.append(
            NormalizedFunction(
                name="mint",
                owner="T",
                visibility="external",
                is_entrypoint=True,
                entrypoint_permissions=[],
                exploration_statements=["balances[to] += v"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_pool_interactions(ctx)
        self.assertTrue(any("external" in f.message.lower() for f in findings))
        self.assertEqual(findings[0].rule_id, "pool_interactions")
        self.assertEqual(findings[0].task_id, "4")

    def test_internal_mint_negative(self):
        model = minimal_audit_model("T")
        model.types[0].functions.append(
            NormalizedFunction(
                name="mint",
                owner="T",
                visibility="internal",
                exploration_statements=["balances[to] += v"],
            ),
        )
        ctx = analysis_context_stub(normalized_model=model)
        findings = run_pool_interactions(ctx)
        ext_alerts = [f for f in findings if "external" in f.message.lower()]
        self.assertEqual(ext_alerts, [])


if __name__ == "__main__":
    unittest.main()
