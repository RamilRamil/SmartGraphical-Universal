"""web_api facade on Soroban-style .rs fixtures."""
import os
import unittest

from smartgraphical.services import web_api
from smartgraphical.services.web_api import ERROR_INVALID_LANGUAGE, WebApiError


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RUST_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "rust", "SorobanViolations.rs")


class WebApiRustFixtureTests(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(RUST_FIXTURE):
            self.skipTest(f"missing fixture: {RUST_FIXTURE}")

    def test_analyze_rust_task_auto_ext(self):
        report = web_api.analyze(RUST_FIXTURE, "1", mode="auditor")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "rust")

    def test_list_tasks_meta_zero_and_contains_rule_1(self):
        payload = web_api.list_tasks("rust")
        self.assertEqual(payload["language"], "rust")
        ids = [t["id"] for t in payload["tasks"]]
        self.assertIn("1", ids)
        self.assertEqual(ids[0], "0")

    def test_graph_shape(self):
        report = web_api.graph(RUST_FIXTURE, language="rust")
        self.assertEqual(report["status"], "ok")
        summary = report["model_summary"]["graph"]
        self.assertGreaterEqual(len(summary["nodes"]), 1)
        self.assertIn("edges", summary)

    def test_unknown_language_go(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.list_tasks("go")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)


if __name__ == "__main__":
    unittest.main()
