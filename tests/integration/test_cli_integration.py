"""Integration tests for run_cli stable report shape."""
import os
import unittest

from smartgraphical.interfaces.cli.main import run_cli


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class CliIntegrationTests(unittest.TestCase):

    def test_run_cli_returns_report_for_single_task(self):
        report = run_cli(
            SIMPLE_AUCTION_PATH,
            selected_task="11",
            output_mode="auditor",
            output_format="json",
            language="solidity",
        )
        self.assertEqual(report["artifact"], SIMPLE_AUCTION_PATH)
        self.assertEqual(report["task"], "11")
        self.assertEqual(report["language"], "solidity")
        self.assertEqual(report["rules_run"], ["11"])
        self.assertIn("findings_count", report)
        self.assertIn("duration_ms", report)
        self.assertGreaterEqual(report["duration_ms"], 0)

    def test_run_cli_auto_detects_language_from_extension(self):
        report = run_cli(
            SIMPLE_AUCTION_PATH,
            selected_task="11",
            output_mode="legacy",
            output_format="json",
        )
        self.assertEqual(report["task"], "11")
        self.assertEqual(report["language"], "solidity")
        self.assertEqual(report["rules_run"], ["11"])
        self.assertFalse(report["graph_rendered"])
        self.assertIn("findings_count", report)


if __name__ == "__main__":
    unittest.main()
