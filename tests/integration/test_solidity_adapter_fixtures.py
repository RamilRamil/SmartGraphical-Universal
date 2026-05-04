"""Adapter-level tests on small checked-in Solidity fixtures (phase 2).

Paths are stable relative to tests/fixtures/solidity/. Assertions document what
SolidityAdapterV0 currently guarantees rather than locking full normalized dumps.

Phase 5 adds narrow JSON-shaped snapshots (type names, function names, state
entity names only). If the reader starts surfacing new state fields, update the
golden string and the docstring with a one-line reason.
"""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0

from tests.integration.pipeline_invariant_helpers import narrow_normalized_model_shape_json

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(TESTS_DIR, "fixtures", "solidity")


def _fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.isfile(path):
        raise AssertionError(f"missing fixture file: {path}")
    return path


class SolidityAdapterFixtureTests(unittest.TestCase):
    def setUp(self):
        self.adapter = SolidityAdapterV0()

    def test_minimal_guard_extracts_require(self):
        path = _fixture("MinimalGuard.sol")
        ctx = self.adapter.parse_source(path)
        model = ctx.normalized_model
        self.assertEqual(len(model.types), 1)
        self.assertEqual(model.types[0].name, "MinimalGuard")
        fn = next(f for f in model.types[0].functions if f.name == "setAmount")
        require_facts = [g for g in fn.guard_facts if g.guard_type == "require"]
        self.assertGreaterEqual(len(require_facts), 1)

    def test_external_mint_exposes_external_mint_entrypoint(self):
        path = _fixture("ExternalMint.sol")
        ctx = self.adapter.parse_source(path)
        mint = next(f for f in ctx.normalized_model.types[0].functions if f.name == "mint")
        self.assertEqual(mint.visibility, "external")
        self.assertTrue(mint.is_entrypoint)

    def test_withdraw_fixture_has_transfer_statement(self):
        path = _fixture("WithdrawNoGuard.sol")
        ctx = self.adapter.parse_source(path)
        pull = next(f for f in ctx.normalized_model.types[0].functions if f.name == "pull")
        self.assertTrue(pull.transfers, msg="pull should record a transfer-like statement")

    def test_mixed_math_records_heavy_arithmetic_statement(self):
        path = _fixture("MixedMath.sol")
        ctx = self.adapter.parse_source(path)
        mix = next(f for f in ctx.normalized_model.types[0].functions if f.name == "mix")
        self.assertTrue(
            mix.computations,
            msg="mix should contribute at least one computation statement for rule 7",
        )
        joined = " ".join(mix.computations)
        self.assertIn("*", joined)
        self.assertIn("/", joined)

    def test_minimal_guard_phase5_shape_snapshot(self):
        """Golden: public storage may be absent from state_entities until reader extends."""
        golden = '{"artifact_language":"solidity","basename":"MinimalGuard.sol","types":[{"functions":["setAmount"],"state_entities":[],"type_name":"MinimalGuard"}]}'
        path = _fixture("MinimalGuard.sol")
        ctx = self.adapter.parse_source(path)
        self.assertEqual(narrow_normalized_model_shape_json(ctx.normalized_model), golden)

    def test_withdraw_fixture_phase5_shape_snapshot(self):
        golden = '{"artifact_language":"solidity","basename":"WithdrawNoGuard.sol","types":[{"functions":["pull"],"state_entities":["balances"],"type_name":"WithdrawNoGuard"}]}'
        path = _fixture("WithdrawNoGuard.sol")
        ctx = self.adapter.parse_source(path)
        self.assertEqual(narrow_normalized_model_shape_json(ctx.normalized_model), golden)


if __name__ == "__main__":
    unittest.main()
