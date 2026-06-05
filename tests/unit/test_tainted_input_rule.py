"""Tests for the portable tainted_input_unguarded_sink rule (feature 015)."""
import os
import unittest

from smartgraphical.core.model import (
    AnalysisContext,
    NormalizedArtifact,
    NormalizedAuditModel,
    NormalizedFunction,
    NormalizedType,
)
from smartgraphical.core.rules.portable import tainted_input_unguarded_sink as rule

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
C_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "c", "TaintedFlow.c")


def _context(function):
    model = NormalizedAuditModel(
        artifact=NormalizedArtifact(path="x", language="c", adapter_name="c_base"),
        types=[NormalizedType(name="C", kind="contract", functions=[function])],
    )
    return AnalysisContext(
        path="x", language="c", reader=None, lines=[], unified_code="",
        rets=[], hierarchy={}, high_connections=[], normalized_model=model,
    )


class TaintedInputRuleTests(unittest.TestCase):
    def test_fires_on_unguarded_path_at_medium(self):
        fn = NormalizedFunction(
            name="h", owner="C",
            taint_paths=[{
                "source": "v", "sink": "transfer", "source_index": -1, "sink_index": 1,
                "source_stmt": "parameter v", "sink_stmt": "transfer(to, v)", "guarded": False,
            }],
        )
        findings = rule.run(_context(fn))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "medium")
        self.assertEqual(findings[0].rule_id, "tainted_input_unguarded_sink")

    def test_silent_on_guarded(self):
        fn = NormalizedFunction(
            name="h", owner="C",
            taint_paths=[{"source": "v", "sink": "transfer", "guarded": True}],
        )
        self.assertEqual(rule.run(_context(fn)), [])

    def test_silent_on_no_paths(self):
        fn = NormalizedFunction(name="h", owner="C", taint_paths=[])
        self.assertEqual(rule.run(_context(fn)), [])


class TaintedInputEndToEndTests(unittest.TestCase):
    def test_fires_on_c_fixture(self):
        if not os.path.isfile(C_FIXTURE):
            self.skipTest("fixture missing")
        from smartgraphical.services import web_api
        report = web_api.analyze_all(C_FIXTURE, "c")
        taint_findings = [
            f for f in report["findings"] if f["rule_id"] == "tainted_input_unguarded_sink"
        ]
        self.assertTrue(taint_findings, "expected a tainted_input_unguarded_sink finding")
        self.assertTrue(all(f["confidence"] == "medium" for f in taint_findings))


if __name__ == "__main__":
    unittest.main()
