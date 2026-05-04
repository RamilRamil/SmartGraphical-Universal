"""Integration tests: full adapter -> AnalysisService pipeline invariants.

Primary reference is SimpleAuction.sol at repo root when present. Checked-in
fixtures under tests/fixtures/solidity/ always run so CI does not depend on
that optional file.

Assertions mirror phase 3 of docs/testing_practices_implementation_plan.md:
known rule_id subset, mandatory finding metadata, no duplicate messages per rule,
every finding carries evidence.
"""
import os
import time
import unittest

from smartgraphical.services.analysis_service import AnalysisService

from tests.integration.pipeline_invariant_helpers import assert_pipeline_findings


TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(TESTS_DIR)
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")
FIXTURE_SOL_DIR = os.path.join(TESTS_DIR, "fixtures", "solidity")

EXPECTED_RULE_IDS = frozenset({
    "contract_version", "unallowed_manipulation", "staking",
    "pool_interactions", "local_points", "exceptions",
    "complicated_calculations", "check_order", "withdraw_check",
    "similar_names", "outer_calls",
})


def _fixture_path(name):
    path = os.path.join(FIXTURE_SOL_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path


class FullPipelineMixin:
    findings = []
    expected_rule_ids = frozenset()

    def test_pipeline_findings_invariants(self):
        assert_pipeline_findings(self, self.findings, self.expected_rule_ids)


@unittest.skipUnless(
    os.path.isfile(SIMPLE_AUCTION_PATH),
    "SimpleAuction.sol not present at repo root (optional golden contract)",
)
class FullPipelineSimpleAuctionTests(FullPipelineMixin, unittest.TestCase):
    findings = []
    expected_rule_ids = EXPECTED_RULE_IDS

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        context = service.analyze(SIMPLE_AUCTION_PATH)
        cls.findings = service.run_all(context)


class FullPipelineWithdrawFixtureTests(FullPipelineMixin, unittest.TestCase):
    """Withdraw + transfer path; fixture is always in the tree."""

    findings = []
    expected_rule_ids = EXPECTED_RULE_IDS

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        path = _fixture_path("WithdrawNoGuard.sol")
        context = service.analyze(path)
        cls.findings = service.run_all(context)


class FullPipelineMintFixtureTests(FullPipelineMixin, unittest.TestCase):
    """External mint path; complements withdraw fixture."""

    findings = []
    expected_rule_ids = EXPECTED_RULE_IDS

    @classmethod
    def setUpClass(cls):
        service = AnalysisService()
        path = _fixture_path("ExternalMint.sol")
        context = service.analyze(path)
        cls.findings = service.run_all(context)


_RUN_INTEGRATION_LARGE = os.environ.get("SMARTGRAPHICAL_RUN_INTEGRATION_LARGE") == "1"
# Loose wall-clock budget per phase 5: full adapter+rules on several small fixtures.
_PIPELINE_BATCH_BUDGET_SEC = float(
    os.environ.get("SMARTGRAPHICAL_PIPELINE_BATCH_BUDGET_SEC", "60")
)


@unittest.skipUnless(
    _RUN_INTEGRATION_LARGE,
    "integration_large disabled; export SMARTGRAPHICAL_RUN_INTEGRATION_LARGE=1 to enable",
)
class IntegrationLargePipelineBudgetTests(unittest.TestCase):
    def test_fixture_batch_analyze_run_all_under_budget(self):
        names = ("MinimalGuard.sol", "WithdrawNoGuard.sol", "ExternalMint.sol", "MixedMath.sol")
        started = time.perf_counter()
        for name in names:
            service = AnalysisService()
            ctx = service.analyze(_fixture_path(name))
            service.run_all(ctx)
        elapsed = time.perf_counter() - started
        self.assertLess(
            elapsed,
            _PIPELINE_BATCH_BUDGET_SEC,
            msg=(
                f"fixture batch exceeded {_PIPELINE_BATCH_BUDGET_SEC}s "
                f"(actual {elapsed:.2f}s); raise budget only if deliberate"
            ),
        )


if __name__ == "__main__":
    unittest.main()
