"""US3 (feature 015): the requires_dataflow C rules that have runners are invoked,
and the new taint facts are additive. Two catalog rules have no runner yet and
are explicitly recorded as a known gap (not silently passing).
"""
import os
import unittest

from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0, build_c_rule_registry
from smartgraphical.core.dataflow.taint import apply_taint
from smartgraphical.core.engine import RuleEngine

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "c", "TaintedFlow.c")

# requires_dataflow catalog rules that ARE registered with a runner (executed).
REGISTERED_DATAFLOW_SLUGS = {
    "io_uring_submission_race_funk",
    "keyswitch_atomicity_violation",
    "unsupported_program_id_divergence",
}
# requires_dataflow catalog rules that have NO runner yet (catalog-only; future work).
CATALOG_ONLY_DATAFLOW_SLUGS = {
    "missing_snapshot_hash_verification",
    "cross_tile_fseq_write",
}


class RequiresDataflowInvokedTests(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(FIXTURE):
            self.skipTest("fixture missing")
        self.ctx = CBaseAdapterV0().parse_source(FIXTURE)
        apply_taint(self.ctx.normalized_model)
        self.registry = build_c_rule_registry()
        self.slugs = {spec.slug for spec in self.registry.values()}

    def test_registered_dataflow_rules_are_invoked(self):
        for slug in REGISTERED_DATAFLOW_SLUGS:
            self.assertIn(slug, self.slugs, f"{slug} must be registered (not skipped)")

    def test_catalog_only_rules_are_a_recorded_gap(self):
        # These are declared in the catalog but lack a runner. Encoded here so the
        # gap is explicit; when a runner is added, move the slug to REGISTERED.
        for slug in CATALOG_ONLY_DATAFLOW_SLUGS:
            self.assertNotIn(slug, self.slugs)

    def test_run_all_invokes_every_registered_rule_without_error(self):
        findings = RuleEngine(self.registry).run_all(self.ctx)
        self.assertIsInstance(findings, list)

    def test_taint_facts_are_additive_for_dataflow_rules(self):
        by_slug = {spec.slug: spec for spec in self.registry.values()}
        for slug in REGISTERED_DATAFLOW_SLUGS:
            runner = by_slug[slug].runner
            with_taint = [f.message for f in runner(self.ctx)]
            for type_entry in self.ctx.normalized_model.types:
                for function in type_entry.functions:
                    function.taint_paths = []
            without_taint = [f.message for f in runner(self.ctx)]
            apply_taint(self.ctx.normalized_model)
            self.assertEqual(
                with_taint, without_taint, f"{slug} output changed by taint facts"
            )


if __name__ == "__main__":
    unittest.main()
