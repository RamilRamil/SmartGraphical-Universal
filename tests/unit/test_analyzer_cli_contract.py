"""Contract tests for the single-shot analyzer CLI (`python -m smartgraphical`).

These lock the batch-consumer surface: envelope shape against the published JSON
Schema, stdout purity, error-as-data with distinguishable exit codes, and
deterministic ordering.
"""
import io
import json
import os
import unittest
import unittest.mock

from smartgraphical.interfaces.cli import analyzer
from tests.support.json_schema import validate


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_PATH = os.path.join(REPO_ROOT, "docs", "contracts", "analyzer-cli-v1.schema.json")
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "WithdrawNoGuard.sol")
GUARD_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")


def load_schema():
    with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run(argv):
    """Invoke the CLI with captured streams; returns (exit_code, stdout, stderr)."""
    stdout, stderr = io.StringIO(), io.StringIO()
    code = analyzer.main(argv, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerCliEnvelopeTests(unittest.TestCase):

    def test_stdout_is_a_single_valid_json_document(self):
        code, stdout, _ = run(["analyze", SOL_FIXTURE, "--mode", "auditor"])
        self.assertEqual(code, analyzer.EXIT_OK)
        document = json.loads(stdout)  # raises if stdout carries anything else
        self.assertEqual(stdout.count("\n"), 1, "compact output must be exactly one line")
        self.assertEqual(document["status"], "ok")
        self.assertEqual(document["schema_version"], analyzer.SCHEMA_VERSION)

    def test_ok_report_conforms_to_published_schema(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE, "--mode", "auditor"])
        self.assertEqual(validate(json.loads(stdout), load_schema()), [])

    def test_graph_report_conforms_and_exposes_nodes_at_top_level(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE, "--graph"])
        document = json.loads(stdout)
        self.assertEqual(validate(document, load_schema()), [])
        self.assertIsInstance(document["graph"]["nodes"], list)
        self.assertTrue(document["graph"]["nodes"], "fixture should yield at least one node")

    def test_graph_is_null_unless_requested(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE])
        self.assertIsNone(json.loads(stdout)["graph"])

    def test_single_task_reports_only_that_rule(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE, "--task", "11"])
        document = json.loads(stdout)
        self.assertEqual(document["task"], "11")
        self.assertEqual(document["rules_run"], ["11"])
        self.assertEqual(validate(document, load_schema()), [])

    def test_clean_target_is_ok_with_zero_findings(self):
        # The distinction that matters to a consumer: "clean" is status ok with
        # findings_count 0 and exit 0, never an error envelope.
        code, stdout, _ = run(["analyze", GUARD_FIXTURE, "--task", "9"])
        document = json.loads(stdout)
        self.assertEqual(code, analyzer.EXIT_OK)
        self.assertEqual(document["status"], "ok")
        self.assertEqual(document["findings_count"], 0)
        self.assertEqual(document["findings"], [])

    def test_pretty_output_is_the_same_document(self):
        _, compact, _ = run(["analyze", SOL_FIXTURE])
        _, pretty, _ = run(["analyze", SOL_FIXTURE, "--pretty"])
        self.assertEqual(json.loads(compact), json.loads(pretty))
        self.assertIn("\n  ", pretty)


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerCliBundleTests(unittest.TestCase):
    """A bundle directory is a valid target and produces the same envelope."""

    def _make_bundle(self, directory):
        import shutil

        from smartgraphical.services.bundle_graph import BUNDLE_MANIFEST_BASENAME

        members = []
        for source in (GUARD_FIXTURE, SOL_FIXTURE):
            name = os.path.basename(source)
            shutil.copy(source, os.path.join(directory, name))
            members.append({"path": name})
        with open(os.path.join(directory, BUNDLE_MANIFEST_BASENAME), "w", encoding="utf-8") as handle:
            json.dump({"members": members}, handle)
        return directory

    def test_bundle_report_conforms_and_attributes_every_finding(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            bundle = self._make_bundle(directory)
            code, stdout, _ = run(["analyze", bundle, "--graph"])
        document = json.loads(stdout)
        self.assertEqual(code, analyzer.EXIT_OK)
        self.assertEqual(validate(document, load_schema()), [])
        self.assertTrue(document["findings"])
        self.assertTrue(all(f["source_file"] for f in document["findings"]))
        self.assertEqual(
            [f["source_file"] for f in document["findings"]],
            sorted(f["source_file"] for f in document["findings"]),
            "findings must be grouped by source file in a stable order",
        )


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerCliErrorContractTests(unittest.TestCase):

    def assert_error(self, argv, expected_code, expected_exit):
        code, stdout, stderr = run(argv)
        self.assertEqual(stdout, "", "a failed run must leave stdout empty")
        document = json.loads(stderr.strip().splitlines()[-1])
        self.assertEqual(validate(document, load_schema()), [])
        self.assertEqual(document["status"], "error")
        self.assertEqual(document["code"], expected_code)
        self.assertEqual(code, expected_exit)

    def test_missing_path_is_an_error_document_on_stderr(self):
        self.assert_error(
            ["analyze", os.path.join(REPO_ROOT, "__does_not_exist__.sol")],
            "invalid_path",
            analyzer.EXIT_INVALID_TARGET,
        )

    def test_invalid_mode_is_a_usage_error(self):
        self.assert_error(
            ["analyze", SOL_FIXTURE, "--mode", "bogus"],
            "invalid_mode",
            analyzer.EXIT_USAGE,
        )

    def test_invalid_language_is_a_usage_error(self):
        self.assert_error(
            ["analyze", SOL_FIXTURE, "--language", "python"],
            "invalid_language",
            analyzer.EXIT_USAGE,
        )

    def test_unknown_task_is_a_usage_error(self):
        self.assert_error(
            ["analyze", SOL_FIXTURE, "--task", "9999"],
            "invalid_task",
            analyzer.EXIT_USAGE,
        )

    def test_missing_arguments_are_an_error_document(self):
        self.assert_error([], "invalid_arguments", analyzer.EXIT_USAGE)

    def test_error_exit_codes_are_distinguishable(self):
        self.assertEqual(
            len({
                analyzer.EXIT_OK,
                analyzer.EXIT_UNEXPECTED,
                analyzer.EXIT_USAGE,
                analyzer.EXIT_INVALID_TARGET,
                analyzer.EXIT_ANALYSIS_FAILED,
            }),
            5,
        )


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerCliDeterminismTests(unittest.TestCase):

    def test_repeated_runs_are_byte_identical(self):
        first = run(["analyze", SOL_FIXTURE, "--graph"])[1]
        second = run(["analyze", SOL_FIXTURE, "--graph"])[1]
        self.assertEqual(first, second)

    def test_document_carries_no_wall_clock_timing(self):
        # duration_ms cannot be byte-stable, so it is a stderr diagnostic only.
        _, stdout, stderr = run(["analyze", SOL_FIXTURE])
        self.assertNotIn("duration_ms", stdout)
        self.assertIn("ms", stderr)

    def test_findings_are_sorted_by_content(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE])
        findings = json.loads(stdout)["findings"]
        keys = [analyzer._finding_sort_key(f) for f in findings]
        self.assertEqual(keys, sorted(keys))

    def test_graph_nodes_and_edges_are_sorted_by_identity(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE, "--graph"])
        graph = json.loads(stdout)["graph"]
        node_ids = [n["id"] for n in graph["nodes"]]
        self.assertEqual(node_ids, sorted(node_ids))
        edge_keys = [(e["source"], e["target"]) for e in graph["edges"]]
        self.assertEqual(edge_keys, sorted(edge_keys))

    def test_shuffled_finding_order_normalizes_to_the_same_list(self):
        _, stdout, _ = run(["analyze", SOL_FIXTURE])
        findings = json.loads(stdout)["findings"]
        self.assertEqual(analyzer._sorted_findings(list(reversed(findings))), findings)


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerCliStdoutPurityTests(unittest.TestCase):
    """stdout must survive an engine that prints.

    Today nothing on the facade path writes to stdout, but a rule or adapter
    could start doing so at any time, and a single stray line silently breaks
    every consumer's parser. These tests inject the stray line on purpose.
    """

    def test_engine_prints_are_redirected_to_stderr(self):
        real = analyzer.facade_analyze_all

        def noisy(*args, **kwargs):
            print("stray progress line from a rule")
            return real(*args, **kwargs)

        with unittest.mock.patch.object(analyzer, "facade_analyze_all", noisy):
            _, stdout, stderr = run(["analyze", SOL_FIXTURE])
        json.loads(stdout)
        self.assertEqual(stdout.count("\n"), 1)
        self.assertIn("stray progress line from a rule", stderr)

    def test_unexpected_engine_crash_never_reaches_stdout(self):
        def boom(*args, **kwargs):
            print("half-finished output")
            raise RuntimeError("adapter exploded")

        with unittest.mock.patch.object(analyzer, "facade_analyze_all", boom):
            code, stdout, stderr = run(["analyze", SOL_FIXTURE])
        self.assertEqual(stdout, "")
        self.assertEqual(code, analyzer.EXIT_UNEXPECTED)
        document = json.loads(stderr.strip().splitlines()[-1])
        self.assertEqual(validate(document, load_schema()), [])
        self.assertEqual(document["code"], "internal_error")
        self.assertIn("half-finished output", stderr)


if __name__ == "__main__":
    unittest.main()
