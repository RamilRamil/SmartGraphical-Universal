"""Smoke tests for the CLI entry point.

These tests guarantee that running `sg_cli.py` as a subprocess does not crash
on a known-good file and fails predictably on a missing file. The rule chosen
(task 11 - outer_calls) does not render a graph, so no extra files are written.
"""
import os
import subprocess
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLI_PATH = os.path.join(REPO_ROOT, "sg_cli.py")
SIMPLE_AUCTION_PATH = os.path.join(REPO_ROOT, "SimpleAuction.sol")


def _run_cli(*extra_args):
    return subprocess.run(
        [sys.executable, CLI_PATH, *extra_args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


class CliSmokeTests(unittest.TestCase):

    def test_happy_path_task_11_auditor_mode_exits_cleanly(self):
        result = _run_cli(SIMPLE_AUCTION_PATH, "11", "auditor")
        self.assertEqual(
            result.returncode, 0,
            msg=f"CLI failed. stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        combined_output = result.stdout + result.stderr
        self.assertTrue(
            "No findings." in combined_output or "[Task" in combined_output,
            msg=f"CLI did not print expected markers. output={combined_output!r}",
        )

    def test_happy_path_legacy_mode_exits_cleanly(self):
        result = _run_cli(SIMPLE_AUCTION_PATH, "11", "legacy")
        self.assertEqual(
            result.returncode, 0,
            msg=f"CLI failed. stdout={result.stdout!r}, stderr={result.stderr!r}",
        )

    def test_invalid_mode_is_rejected(self):
        result = _run_cli(SIMPLE_AUCTION_PATH, "11", "bogus_mode")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode must be one of", result.stdout + result.stderr)

    def test_missing_file_fails_cleanly(self):
        result = _run_cli(os.path.join(REPO_ROOT, "__no_such_file__.sol"), "11", "auditor")
        self.assertNotEqual(result.returncode, 0)

    def test_missing_argument_fails_cleanly(self):
        result = _run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Please provide", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
