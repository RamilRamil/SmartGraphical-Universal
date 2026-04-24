"""Unit tests for smartgraphical.services.web_api facade."""
import os
import unittest

from smartgraphical.services import web_api
from smartgraphical.services.web_api import (
    ERROR_INVALID_LANGUAGE,
    ERROR_INVALID_MODE,
    ERROR_INVALID_PATH,
    ERROR_INVALID_TASK,
    WebApiError,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class WebApiHealthTests(unittest.TestCase):

    def test_health_returns_stable_shape(self):
        report = web_api.health()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["service"], "smartgraphical")
        self.assertIn("solidity", report["supported_languages"])
        self.assertIn("c", report["supported_languages"])
        self.assertIn("auditor", report["supported_modes"])


class WebApiAnalyzeTests(unittest.TestCase):

    def test_analyze_returns_findings_for_known_task(self):
        report = web_api.analyze(SIMPLE_AUCTION_PATH, "11", language="solidity", mode="auditor")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "solidity")
        self.assertEqual(report["mode"], "auditor")
        self.assertEqual(report["task"], "11")
        self.assertEqual(report["rules_run"], ["11"])
        self.assertIsInstance(report["findings"], list)
        self.assertEqual(report["findings_count"], len(report["findings"]))
        self.assertFalse(report["graph_rendered"])
        self.assertIn("duration_ms", report)

    def test_analyze_auto_detects_language(self):
        report = web_api.analyze(SIMPLE_AUCTION_PATH, "11")
        self.assertEqual(report["language"], "solidity")

    def test_analyze_rejects_missing_path(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze("__missing__.sol", "11")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PATH)

    def test_analyze_rejects_invalid_mode(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SIMPLE_AUCTION_PATH, "11", language="solidity", mode="bad")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_MODE)

    def test_analyze_rejects_invalid_language(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SIMPLE_AUCTION_PATH, "11", language="rust")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)

    def test_analyze_rejects_unknown_task(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SIMPLE_AUCTION_PATH, "999", language="solidity")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_TASK)

    def test_analyze_rejects_empty_task(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SIMPLE_AUCTION_PATH, "   ", language="solidity")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_TASK)


class WebApiAnalyzeAllTests(unittest.TestCase):

    def test_analyze_all_runs_every_rule(self):
        report = web_api.analyze_all(SIMPLE_AUCTION_PATH, language="solidity")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["task"], "all")
        self.assertGreater(len(report["rules_run"]), 1)
        self.assertEqual(report["findings_count"], len(report["findings"]))

    def test_analyze_all_rejects_missing_path(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze_all("__missing__.sol")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PATH)


class WebApiGraphTests(unittest.TestCase):

    def test_graph_returns_model_summary(self):
        report = web_api.graph(SIMPLE_AUCTION_PATH, language="solidity")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "solidity")
        summary = report["model_summary"]
        self.assertIn("types_count", summary)
        self.assertIn("functions_count", summary)
        self.assertIn("call_edges_count", summary)
        self.assertGreaterEqual(summary["types_count"], 1)

    def test_graph_rejects_missing_path(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.graph("__missing__.sol")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PATH)


class WebApiListTasksTests(unittest.TestCase):

    def test_list_tasks_returns_solidity_catalog(self):
        payload = web_api.list_tasks("solidity")
        self.assertEqual(payload["language"], "solidity")
        self.assertGreater(len(payload["tasks"]), 1)
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("11", ids)
        self.assertEqual(ids[-1], "all")
        meta_task = payload["tasks"][-1]
        self.assertEqual(meta_task["kind"], "meta")
        rule_task = next(task for task in payload["tasks"] if task["id"] == "11")
        self.assertEqual(rule_task["kind"], "rule")
        self.assertTrue(rule_task["title"])

    def test_list_tasks_returns_c_catalog(self):
        payload = web_api.list_tasks("c")
        self.assertEqual(payload["language"], "c")
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("101", ids)
        self.assertEqual(ids[-1], "all")

    def test_list_tasks_normalizes_case(self):
        payload = web_api.list_tasks("Solidity")
        self.assertEqual(payload["language"], "solidity")

    def test_list_tasks_rejects_unknown_language(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.list_tasks("rust")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)

    def test_list_tasks_rejects_empty_language(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.list_tasks("")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)


class WebApiErrorTests(unittest.TestCase):

    def test_error_to_dict_preserves_code_and_message(self):
        error = WebApiError(ERROR_INVALID_PATH, "nope")
        payload = error.to_dict()
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], ERROR_INVALID_PATH)
        self.assertEqual(payload["message"], "nope")


if __name__ == "__main__":
    unittest.main()
