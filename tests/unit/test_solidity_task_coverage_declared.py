"""Phase 4: declared Solidity task coverage must match build_rule_registry().

Updating the registry requires updating tests/fixtures/solidity_task_coverage.json.
"""
import json
import os
import unittest

from smartgraphical.adapters.solidity.adapter import build_rule_registry
from smartgraphical.services.web_api import list_tasks

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fixtures",
    "solidity_task_coverage.json",
)

ALLOWED_PRIMARY = frozenset({"model_unit", "e2e_only", "exempt"})


class SolidityTaskCoverageContractTests(unittest.TestCase):
    """Keep UI/API task catalog aligned with tracked coverage metadata."""

    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH, encoding="utf-8") as handle:
            cls._manifest = json.load(handle)

    def test_fixture_declares_language_solidity(self):
        self.assertEqual(self._manifest.get("language"), "solidity")

    def test_registry_keys_match_manifest(self):
        registry = build_rule_registry()
        reg_ids = set(registry.keys())
        declared = set(self._manifest["registry_tasks"].keys())
        self.assertEqual(
            reg_ids,
            declared,
            msg=(
                "Mismatch: registry vs solidity_task_coverage.json. "
                f"only_in_registry={reg_ids - declared} only_in_manifest={declared - reg_ids}"
            ),
        )

    def test_every_task_slug_matches_registry(self):
        registry = build_rule_registry()
        for task_id, spec in registry.items():
            entry = self._manifest["registry_tasks"][task_id]
            self.assertEqual(
                entry["slug"],
                spec.slug,
                msg=f"task {task_id} slug differs from RuleSpec.slug",
            )

    def test_primary_coverage_is_allowlisted(self):
        for task_id, entry in self._manifest["registry_tasks"].items():
            primary = entry["primary_coverage"]
            self.assertIn(
                primary,
                ALLOWED_PRIMARY,
                msg=f"task {task_id}: unknown primary_coverage {primary!r}",
            )

    def test_meta_tasks_not_in_registry(self):
        registry = build_rule_registry()
        for meta_id in self._manifest["meta_tasks"]:
            self.assertNotIn(
                meta_id,
                registry,
                msg=f"meta task id {meta_id!r} must not duplicate a registry RuleSpec task id",
            )

    def test_documented_primary_coverage_values_present(self):
        documented = self._manifest.get("primary_coverage_values_documented", [])
        self.assertEqual(set(documented), ALLOWED_PRIMARY)

    def test_web_api_tasks_list_aligns_with_registry(self):
        """list_tasks exposes the same ids as RuleEngine registry plus trailing meta."""
        registry = build_rule_registry()
        payload = list_tasks("solidity")
        ids = [t["id"] for t in payload["tasks"]]
        self.assertEqual(ids[-1], "all")
        self.assertEqual(set(ids[:-1]), set(registry.keys()))


if __name__ == "__main__":
    unittest.main()
