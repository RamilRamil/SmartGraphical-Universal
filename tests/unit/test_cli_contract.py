"""Unit tests for CLI argument contract and validation."""
import os
import unittest

from smartgraphical.interfaces.cli.main import (
    ALLOWED_MODES,
    ALLOWED_OUTPUT_FORMATS,
    CliUserError,
    parse_cli_args,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


class CliArgumentContractTests(unittest.TestCase):

    def test_parse_cli_args_uses_defaults(self):
        source_path, selected_task, output_mode, output_format, language = parse_cli_args(
            ["sg_cli.py", SIMPLE_AUCTION_PATH]
        )
        self.assertEqual(source_path, SIMPLE_AUCTION_PATH)
        self.assertIsNone(selected_task)
        self.assertEqual(output_mode, "legacy")
        self.assertEqual(output_format, "text")
        self.assertEqual(language, "solidity")

    def test_parse_cli_args_allows_known_mode_and_format(self):
        source_path, selected_task, output_mode, output_format, language = parse_cli_args(
            ["sg_cli.py", SIMPLE_AUCTION_PATH, "11", "auditor", "json", "solidity"]
        )
        self.assertEqual(source_path, SIMPLE_AUCTION_PATH)
        self.assertEqual(selected_task, "11")
        self.assertIn(output_mode, ALLOWED_MODES)
        self.assertIn(output_format, ALLOWED_OUTPUT_FORMATS)
        self.assertEqual(language, "solidity")

    def test_parse_cli_args_rejects_missing_path(self):
        with self.assertRaises(CliUserError):
            parse_cli_args(["sg_cli.py"])

    def test_parse_cli_args_rejects_unknown_file(self):
        with self.assertRaises(CliUserError):
            parse_cli_args(["sg_cli.py", "__missing__.sol"])

    def test_parse_cli_args_rejects_invalid_mode(self):
        with self.assertRaises(CliUserError):
            parse_cli_args(["sg_cli.py", SIMPLE_AUCTION_PATH, "11", "bad_mode"])

    def test_parse_cli_args_rejects_invalid_output_format(self):
        with self.assertRaises(CliUserError):
            parse_cli_args(["sg_cli.py", SIMPLE_AUCTION_PATH, "11", "auditor", "yaml"])

    def test_parse_cli_args_rejects_invalid_language(self):
        with self.assertRaises(CliUserError):
            parse_cli_args(["sg_cli.py", SIMPLE_AUCTION_PATH, "11", "auditor", "json", "rust"])


if __name__ == "__main__":
    unittest.main()
