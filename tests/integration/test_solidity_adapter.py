"""Integration test: parse optional local golden contract at repo root.

Requires LocalGolden.sol in the repo root; skipped when absent. Other tests
use checked-in fixtures under tests/fixtures/.

This test exercises only the adapter layer. It asserts structural properties
(names, counts, presence of keys) rather than full message strings, so it
stays stable under minor refactorings.
"""
import os
import unittest

from smartgraphical.adapters.solidity.adapter import SolidityAdapterV0


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOCAL_GOLDEN_PATH = os.path.join(REPO_ROOT, "LocalGolden.sol")


@unittest.skipUnless(
    os.path.isfile(LOCAL_GOLDEN_PATH),
    "LocalGolden.sol not present at repo root (optional local golden contract)",
)
class OptionalLocalGoldenAdapterTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.context = SolidityAdapterV0().parse_source(LOCAL_GOLDEN_PATH)
        cls.model = cls.context.normalized_model
        cls.type_name = cls.model.types[0].name

    def test_artifact_metadata_is_set(self):
        self.assertEqual(self.model.artifact.language, "solidity")
        self.assertEqual(self.model.artifact.adapter_name, "SolidityAdapterV0")
        self.assertEqual(self.model.artifact.path, LOCAL_GOLDEN_PATH)

    def test_exactly_one_type_is_parsed(self):
        self.assertEqual(len(self.model.types), 1)
        self.assertEqual(self.model.types[0].name, self.type_name)

    def test_expected_functions_are_present(self):
        function_names = {f.name for f in self.model.types[0].functions}
        self.assertIn("bid", function_names)
        self.assertIn("withdraw", function_names)
        self.assertIn("endAuction", function_names)

    def test_bid_function_has_require_guards(self):
        bid = self._function("bid")
        require_guards = [g for g in bid.guard_facts if g.guard_type == "require"]
        self.assertGreaterEqual(len(require_guards), 2)

    def test_withdraw_function_reports_a_transfer(self):
        withdraw = self._function("withdraw")
        self.assertTrue(
            withdraw.transfers or any(
                "transfer(" in call.source_statement for call in withdraw.external_calls
            ),
            msg="withdraw should expose a transfer-like effect on the normalized model",
        )

    def test_state_entities_include_core_variables(self):
        state_names = {e.name for e in self.model.types[0].state_entities}
        for expected in {"owner", "highestBid", "highestBidder", "bids"}:
            self.assertIn(expected, state_names)

    def test_evidence_index_is_populated_for_known_functions(self):
        for function_name in ("bid", "withdraw"):
            function_key = f"{self.type_name}.{function_name}"
            self.assertIn(function_key, self.model.findings_data.evidence_index)

    def test_exploration_notes_are_populated(self):
        notes = self.model.exploration_data.function_notes
        bid_key = f"{self.type_name}.bid"
        self.assertIn(bid_key, notes)
        self.assertGreater(notes[bid_key]["statement_count"], 0)

    def _function(self, function_name):
        for function in self.model.types[0].functions:
            if function.name == function_name:
                return function
        self.fail(f"Function '{function_name}' missing from parsed model")


if __name__ == "__main__":
    unittest.main()
