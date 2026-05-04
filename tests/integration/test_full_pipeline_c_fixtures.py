"""Full C pipeline invariants (adapter + C rule registry) on checked-in .c fixtures.

Uses the same finding-shape checks as Solidity pipeline tests (phase 3 for C).
"""
import os
import unittest

from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0, build_c_rule_registry
from smartgraphical.core.engine import RuleEngine
from smartgraphical.services.analysis_service import AnalysisService

from tests.integration.pipeline_invariant_helpers import assert_pipeline_findings

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_C_DIR = os.path.join(TESTS_DIR, "fixtures", "c")

EXPECTED_C_RULE_IDS = frozenset(spec.slug for spec in build_c_rule_registry().values())


def _c_fixture(name):
    path = os.path.join(FIXTURE_C_DIR, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path


def _c_service():
    return AnalysisService(
        adapter=CBaseAdapterV0(),
        rule_engine=RuleEngine(build_c_rule_registry()),
    )


class CFullPipelineMinimalTuTests(unittest.TestCase):
    findings = []

    @classmethod
    def setUpClass(cls):
        svc = _c_service()
        ctx = svc.analyze(_c_fixture("MinimalTu.c"))
        cls.findings = svc.run_all(ctx)

    def test_pipeline_findings_invariants(self):
        assert_pipeline_findings(self, self.findings, EXPECTED_C_RULE_IDS)


class CFullPipelineFloatCastTests(unittest.TestCase):
    findings = []

    @classmethod
    def setUpClass(cls):
        svc = _c_service()
        ctx = svc.analyze(_c_fixture("FloatToUintCast.c"))
        cls.findings = svc.run_all(ctx)

    def test_pipeline_findings_invariants(self):
        assert_pipeline_findings(self, self.findings, EXPECTED_C_RULE_IDS)

    def test_float_cast_triggers_task_101(self):
        self.assertTrue(
            any(f.rule_id == "non_saturating_float_cast" for f in self.findings),
            msg="expected rule 101 to fire on (uint64_t)(v * 1.0) pattern",
        )


if __name__ == "__main__":
    unittest.main()
