"""Adapter-level integration tests on small checked-in .c fixtures (phase 2 for C).

See docs/testing_practices_implementation_plan.md and docs/testing_c_rule_coverage_matrix.md.
"""
import os
import unittest

from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0

from tests.integration.pipeline_invariant_helpers import narrow_normalized_model_shape_json

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(TESTS_DIR, "fixtures", "c")


def _fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.isfile(path):
        raise AssertionError(f"missing fixture file: {path}")
    return path


class CAdapterFixtureTests(unittest.TestCase):
    def setUp(self):
        self.adapter = CBaseAdapterV0()

    def test_minimal_tu_extracts_static_and_external(self):
        path = _fixture("MinimalTu.c")
        ctx = self.adapter.parse_source(path)
        model = ctx.normalized_model
        self.assertEqual(len(model.types), 1)
        self.assertEqual(model.types[0].name, "MinimalTu")
        names = {fn.name for fn in model.types[0].functions}
        self.assertIn("internal_dup", names)
        self.assertIn("public_add", names)
        internal_dup = next(f for f in model.types[0].functions if f.name == "internal_dup")
        public_add = next(f for f in model.types[0].functions if f.name == "public_add")
        self.assertEqual(internal_dup.visibility, "internal")
        self.assertFalse(internal_dup.is_entrypoint)
        self.assertEqual(public_add.visibility, "external")
        self.assertTrue(public_add.is_entrypoint)

    def test_float_cast_fixture_has_statements(self):
        path = _fixture("FloatToUintCast.c")
        ctx = self.adapter.parse_source(path)
        fn = next(f for f in ctx.normalized_model.types[0].functions if f.name == "cast_double_to_uint64")
        self.assertTrue(fn.exploration_statements)
        joined = " ".join(fn.exploration_statements)
        self.assertIn("uint64_t", joined)
        self.assertIn("1.0", joined)

    def test_minimal_tu_phase5_shape_snapshot(self):
        golden = '{"artifact_language":"c","basename":"MinimalTu.c","types":[{"functions":["internal_dup","public_add"],"state_entities":[],"type_name":"MinimalTu"}]}'
        path = _fixture("MinimalTu.c")
        ctx = self.adapter.parse_source(path)
        self.assertEqual(narrow_normalized_model_shape_json(ctx.normalized_model), golden)

    def test_float_cast_fixture_phase5_shape_snapshot(self):
        golden = '{"artifact_language":"c","basename":"FloatToUintCast.c","types":[{"functions":["cast_double_to_uint64"],"state_entities":[],"type_name":"FloatToUintCast"}]}'
        path = _fixture("FloatToUintCast.c")
        ctx = self.adapter.parse_source(path)
        self.assertEqual(narrow_normalized_model_shape_json(ctx.normalized_model), golden)


if __name__ == "__main__":
    unittest.main()
