"""Integration tests: full adapter -> AnalysisService pipeline invariants.

Primary reference is SimpleAuction.sol at repo root when present. Checked-in
fixtures under tests/fixtures/solidity/ always run so CI does not depend on
that optional file.

Assertions mirror phase 3 of docs/testing_practices_implementation_plan.md:
known rule_id subset, mandatory finding metadata, no duplicate messages per rule,
every finding carries evidence.
"""
import os
import unittest
from collections import Counter

from smartgraphical.services.analysis_service import AnalysisService


TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")
FIXTURE_SOL_DIR = os.path.join(TESTS_DIR, "fixtures", "solidity")

EXPECTED_RULE_IDS = {
    "contract_version", "unallowed_manipulation", "staking",
    "pool_interactions", "local_points", "exceptions",
    "complicated_calculations", "check_order", "withdraw_check",
    "similar_names", "outer_calls",
}


def _fixture_path(name):
    path = os.path.join(FIXTURE_SOL_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path


class FullPipelineMixin:
    findings = []
    """Subclasses must set `findings` in setUpClass."""

    def test_pipeline_returns_a_list(self):
        self.assertIsInstance(self.findings, list)

    def test_all_finding_rule_ids_are_known(self):
        seen_rule_ids = {f.rule_id for f in self.findings}
        unknown = seen_rule_ids - EXPECTED_RULE_IDS
        self.assertFalse(
            unknown,
            msg=f"Unexpected rule_id values (update EXPECTED_RULE_IDS if intentional): {unknown}",
        )

    def test_findings_have_mandatory_metadata(self):
        for finding in self.findings:
            self.assertTrue(finding.rule_id)
            self.assertTrue(finding.title)
            self.assertTrue(finding.task_id)
            self.assertTrue(finding.message)

    def test_no_exact_duplicate_messages_within_the_same_rule(self):
        grouped = Counter((f.rule_id, f.message) for f in self.findings)
        duplicated = [key for key, count in grouped.items() if count > 1]
        self.assertEqual(duplicated, [], msg=f"Duplicate findings inside same rule: {duplicated}")

    def test_every_finding_carries_at_least_one_evidence(self):
        for finding in self.findings:
            self.assertTrue(
                finding.evidences,
                msg=f"Finding {finding.rule_id} has no evidence",
            )


@unittest.skipUnless(
    os.path.isfile(SIMPLE_AUCTION_PATH),
    "SimpleAuction.sol not present at repo root (optional golden contract)",
)
class FullPipelineSimpleAuctionTests(FullPipelineMixin, unittest.TestCase):
    findings = []

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        context = service.analyze(SIMPLE_AUCTION_PATH)
        cls.findings = service.run_all(context)


class FullPipelineWithdrawFixtureTests(FullPipelineMixin, unittest.TestCase):
    """Withdraw + transfer path; fixture is always in the tree."""

    findings = []

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        path = _fixture_path("WithdrawNoGuard.sol")
        context = service.analyze(path)
        cls.findings = service.run_all(context)


class FullPipelineMintFixtureTests(FullPipelineMixin, unittest.TestCase):
    """External mint path; complements withdraw fixture."""

    findings = []

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        path = _fixture_path("ExternalMint.sol")
        context = service.analyze(path)
        cls.findings = service.run_all(context)


if __name__ == "__main__":
    unittest.main()
