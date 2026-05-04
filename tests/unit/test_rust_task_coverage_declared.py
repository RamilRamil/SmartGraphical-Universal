"""Rust/Soroban: declared tasks must match build_rust_rule_registry."""
import json
import os
import unittest

from smartgraphical.adapters.rust_stellar.adapter import build_rust_rule_registry
from smartgraphical.services.web_api import list_tasks

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "fixtures",
    "rust_task_coverage.json",
)


class RustTaskCoverageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE_PATH, encoding="utf-8") as handle:
            cls._manifest = json.load(handle)

    def test_fixture_language(self):
        self.assertEqual(self._manifest.get("language"), "rust")

    def test_registry_ids_and_slugs(self):
        registry = build_rust_rule_registry()
        reg_ids = set(registry.keys())
        rows = self._manifest.get("tasks", [])
        decl_ids = {row["id"] for row in rows}
        self.assertEqual(reg_ids, decl_ids)
        decl_slug = {row["id"]: row["slug"] for row in rows}
        for tid, spec in registry.items():
            self.assertEqual(decl_slug[tid], spec.slug)

    def test_web_api_list_tasks(self):
        registry = build_rust_rule_registry()
        payload = list_tasks("rust")
        ids = [t["id"] for t in payload["tasks"]]
        self.assertEqual(ids[-1], "all")
        self.assertEqual(set(ids[:-1]), set(registry.keys()))


if __name__ == "__main__":
    unittest.main()
