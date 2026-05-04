"""Unit smoke tests for Soroban rule runners."""
import os
import unittest

from smartgraphical.adapters.rust_stellar.adapter import (
    RustStellarAdapterV0,
    build_rust_rule_registry,
)
from smartgraphical.core.engine import RuleEngine


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "rust", "SorobanViolations.rs")


class RustStellarFixtureRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(FIXTURE):
            raise unittest.SkipTest(f"missing fixture: {FIXTURE}")
        cls.adapter = RustStellarAdapterV0()

    def setUp(self):
        self.context = self.adapter.parse_source(FIXTURE)
        self.engine = RuleEngine(build_rust_rule_registry())

    def test_missing_auth_fires_on_violating_entry(self):
        findings = self.engine.run_task(self.context, "201")
        slugs = {f.rule_id for f in findings}
        self.assertIn("missing_auth_check", slugs)

    def test_unbounded_instance_fire(self):
        findings = self.engine.run_task(self.context, "202")
        slugs = {f.rule_id for f in findings}
        self.assertIn("unbounded_instance_storage_growth", slugs)

    def test_invoke_without_try_fire(self):
        findings = self.engine.run_task(self.context, "203")
        slugs = {f.rule_id for f in findings}
        self.assertIn("unhandled_cross_contract_failure", slugs)

    def test_complex_params_fire(self):
        findings = self.engine.run_task(self.context, "204")
        slugs = {f.rule_id for f in findings}
        self.assertIn("dangerous_raw_val_conversion", slugs)

    def test_missing_ttl_constructor_loop_assert(self):
        rules = {"205": "missing_ttl_extension", "206": "improper_error_signaling",
                 "207": "resource_limit_exhaustion_loop", "208": "constructor_reinitialization_risk"}
        for tid, slug in rules.items():
            with self.subTest(task=tid):
                findings = self.engine.run_task(self.context, tid)
                fs = {f.rule_id for f in findings}
                self.assertIn(slug, fs, msg=f"expected finding for {slug}")


if __name__ == "__main__":
    unittest.main()
