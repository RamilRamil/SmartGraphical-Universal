"""web_api facade on Go .go fixtures."""
import os
import unittest

from smartgraphical.services import web_api
from smartgraphical.services.web_api import ERROR_INVALID_LANGUAGE, WebApiError


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GO_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "go", "GoViolations.go")


class WebApiGoFixtureTests(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(GO_FIXTURE):
            self.skipTest(f"missing fixture: {GO_FIXTURE}")

    def test_analyze_go_task_auto_ext(self):
        report = web_api.analyze(GO_FIXTURE, "4", mode="auditor")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "go")
        self.assertGreaterEqual(report["findings_count"], 1)

    def test_list_tasks_meta_zero_and_contains_rule_1(self):
        payload = web_api.list_tasks("go")
        self.assertEqual(payload["language"], "go")
        ids = [t["id"] for t in payload["tasks"]]
        self.assertIn("1", ids)
        self.assertIn("18", ids)
        self.assertEqual(ids[0], "0")

    def test_graph_shape(self):
        report = web_api.graph(GO_FIXTURE, language="go")
        self.assertEqual(report["status"], "ok")
        summary = report["model_summary"]["graph"]
        self.assertGreaterEqual(len(summary["nodes"]), 1)
        self.assertIn("edges", summary)

    def test_analyze_all_runs_eighteen_rules(self):
        report = web_api.analyze_all(GO_FIXTURE, language="go")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(len(report["rules_run"]), 18)

    def test_unknown_language_python(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.list_tasks("python")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)


if __name__ == "__main__":
    unittest.main()
