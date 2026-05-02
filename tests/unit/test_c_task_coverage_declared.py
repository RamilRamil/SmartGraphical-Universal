"""Phase 4 (C): declared task coverage must match build_c_rule_registry().

Updating the C registry requires updating tests/fixtures/c_task_coverage.json.
"""
import json
import os
import unittest

from smartgraphical.adapters.c_base.adapter import build_c_rule_registry
from smartgraphical.services.web_api import list_tasks

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fixtures",
    "c_task_coverage.json",
)

ALLOWED_PRIMARY = frozenset({"model_unit", "e2e_only", "exempt"})


class CTaskCoverageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH, encoding="utf-8") as handle:
            cls._manifest = json.load(handle)

    def test_fixture_declares_language_c(self):
        self.assertEqual(self._manifest.get("language"), "c")

    def test_registry_keys_match_manifest(self):
        registry = build_c_rule_registry()
        reg_ids = set(registry.keys())
        declared = set(self._manifest["registry_tasks"].keys())
        self.assertEqual(
            reg_ids,
            declared,
            msg=(
                "Mismatch: C registry vs c_task_coverage.json. "
                f"only_in_registry={reg_ids - declared} only_in_manifest={declared - reg_ids}"
            ),
        )

    def test_every_task_slug_matches_registry(self):
        registry = build_c_rule_registry()
        for task_id, spec in registry.items():
            entry = self._manifest["registry_tasks"][task_id]
            self.assertEqual(entry["slug"], spec.slug, msg=f"C task {task_id} slug mismatch")

    def test_primary_coverage_is_allowlisted(self):
        for task_id, entry in self._manifest["registry_tasks"].items():
            primary = entry["primary_coverage"]
            self.assertIn(primary, ALLOWED_PRIMARY, msg=f"C task {task_id}: unknown {primary!r}")

    def test_meta_tasks_not_in_registry(self):
        registry = build_c_rule_registry()
        for meta_id in self._manifest["meta_tasks"]:
            self.assertNotIn(meta_id, registry)

    def test_documented_primary_coverage_values_present(self):
        documented = self._manifest.get("primary_coverage_values_documented", [])
        self.assertEqual(set(documented), ALLOWED_PRIMARY)

    def test_web_api_tasks_list_aligns_with_registry(self):
        registry = build_c_rule_registry()
        payload = list_tasks("c")
        ids = [t["id"] for t in payload["tasks"]]
        self.assertEqual(ids[-1], "all")
        self.assertEqual(set(ids[:-1]), set(registry.keys()))


if __name__ == "__main__":
    unittest.main()
