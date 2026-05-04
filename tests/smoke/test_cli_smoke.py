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
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")


def _run_cli(*extra_args):
    return subprocess.run(
        [sys.executable, CLI_PATH, *extra_args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture MinimalGuard.sol missing")
class CliSmokeTests(unittest.TestCase):

    def test_happy_path_task_11_auditor_mode_exits_cleanly(self):
        result = _run_cli(SOL_FIXTURE, "11", "auditor")
        self.assertEqual(
            result.returncode, 0,
            msg=f"CLI failed. stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        self.assertTrue(result.stdout or result.stderr)

    def test_happy_path_legacy_mode_exits_cleanly(self):
        result = _run_cli(SOL_FIXTURE, "11", "legacy")
        self.assertEqual(
            result.returncode, 0,
            msg=f"CLI failed. stdout={result.stdout!r}, stderr={result.stderr!r}",
        )

    def test_json_output_mode_returns_structured_payload(self):
        result = _run_cli(SOL_FIXTURE, "11", "auditor", "json")
        self.assertEqual(result.returncode, 0)
        self.assertIn("\"artifact\"", result.stdout)
        self.assertIn("\"rules_run\"", result.stdout)
        self.assertIn("\"duration_ms\"", result.stdout)

    def test_invalid_mode_is_rejected(self):
        result = _run_cli(SOL_FIXTURE, "11", "bogus_mode")
        self.assertEqual(result.returncode, 2)
        self.assertIn("mode must be one of", result.stdout + result.stderr)

    def test_missing_file_fails_cleanly(self):
        result = _run_cli(os.path.join(REPO_ROOT, "__no_such_file__.sol"), "11", "auditor")
        self.assertEqual(result.returncode, 2)
        self.assertIn("source file not found", result.stdout + result.stderr)

    def test_missing_argument_fails_cleanly(self):
        result = _run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Please provide", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
