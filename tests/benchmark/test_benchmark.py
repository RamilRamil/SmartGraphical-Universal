"""Benchmark corpus tests (feature 014): metric logic + label loading + corpus."""
import json
import os
import shutil
import tempfile
import unittest

from smartgraphical.benchmark import corpus


def finding(rule_id, type_name="", function_name=""):
    return {
        "rule_id": rule_id,
        "evidences": [{"type_name": type_name, "function_name": function_name}],
    }


class EvaluateTests(unittest.TestCase):
    def test_match_key(self):
        self.assertEqual(corpus.match_key(finding("r", "T", "f")), ("r", "T", "f"))
        self.assertEqual(corpus.match_key({"rule_id": "r", "evidences": []}), ("r", "", ""))

    def test_recall_precision_unexpected(self):
        findings = [finding("a", "C", "f1"), finding("b", "C", "f2"), finding("c", "C", "f3")]
        label = {
            "example": "X.sol",
            "expected": [
                {"rule_id": "a", "type_name": "C", "function_name": "f1"},
                {"rule_id": "z", "type_name": "C", "function_name": "f9"},  # missed
            ],
            "false_positives": [{"rule_id": "b", "type_name": "C", "function_name": "f2"}],
        }
        res = corpus.evaluate(findings, label)
        self.assertEqual(res["expected_total"], 2)
        self.assertEqual(len(res["found"]), 1)
        self.assertEqual(len(res["missed"]), 1)
        self.assertEqual(len(res["labeled_fp"]), 1)
        self.assertEqual(len(res["unexpected"]), 1)  # c/C/f3
        self.assertAlmostEqual(res["recall"], 0.5)
        self.assertAlmostEqual(res["precision"], 0.5)
        self.assertIn("a", res["by_rule"])

    def test_empty_expected_is_na(self):
        res = corpus.evaluate(
            [finding("a", "C", "f")],
            {"example": "X", "expected": [], "false_positives": []},
        )
        self.assertIsNone(res["recall"])
        self.assertEqual(len(res["unexpected"]), 1)

    def test_same_key_collapses(self):
        findings = [finding("a", "C", "f"), finding("a", "C", "f")]
        label = {
            "example": "X",
            "expected": [{"rule_id": "a", "type_name": "C", "function_name": "f"}],
            "false_positives": [],
        }
        res = corpus.evaluate(findings, label)
        self.assertEqual(res["recall"], 1.0)
        self.assertEqual(len(res["found"]), 1)

    def test_labeled_fp_not_unexpected(self):
        findings = [finding("b", "C", "g")]
        label = {
            "example": "X",
            "expected": [],
            "false_positives": [{"rule_id": "b", "type_name": "C", "function_name": "g"}],
        }
        res = corpus.evaluate(findings, label)
        self.assertEqual(res["unexpected"], [])
        self.assertEqual(res["precision"], 0.0)  # 0 / (0 + 1)


class LoadLabelsTests(unittest.TestCase):
    def _write(self, content):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        self.addCleanup(os.remove, path)
        return path

    def test_valid(self):
        path = self._write(json.dumps({"example": "X.sol", "expected": [{"rule_id": "a"}]}))
        data = corpus.load_labels(path)
        self.assertEqual(data["example"], "X.sol")
        self.assertEqual(data["false_positives"], [])

    def test_malformed_json(self):
        with self.assertRaises(corpus.BenchmarkError):
            corpus.load_labels(self._write("{not json"))

    def test_missing_example(self):
        with self.assertRaises(corpus.BenchmarkError):
            corpus.load_labels(self._write(json.dumps({"expected": []})))

    def test_entry_missing_rule_id(self):
        with self.assertRaises(corpus.BenchmarkError):
            corpus.load_labels(self._write(json.dumps({"example": "X", "expected": [{"type_name": "C"}]})))

    def test_not_found(self):
        with self.assertRaises(corpus.BenchmarkError):
            corpus.load_labels("/no/such/file.json")


class RunCorpusTests(unittest.TestCase):
    def setUp(self):
        self.labels_dir = tempfile.mkdtemp()
        self.examples_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.labels_dir)
        self.addCleanup(shutil.rmtree, self.examples_dir)
        open(os.path.join(self.examples_dir, "X.sol"), "w").close()
        with open(os.path.join(self.labels_dir, "X.sol.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "example": "X.sol",
                    "expected": [{"rule_id": "a", "type_name": "C", "function_name": "f"}],
                    "false_positives": [{"rule_id": "b", "type_name": "C", "function_name": "g"}],
                },
                handle,
            )

    def _fake_analyze(self, path, language="solidity"):
        return {"findings": [finding("a", "C", "f"), finding("b", "C", "g"), finding("c", "C", "h")]}

    def test_deterministic_and_correct(self):
        r1 = corpus.run_corpus(self.labels_dir, self.examples_dir, self._fake_analyze)
        r2 = corpus.run_corpus(self.labels_dir, self.examples_dir, self._fake_analyze)
        self.assertEqual(r1, r2)
        self.assertEqual(r1["overall"]["recall"], 1.0)
        self.assertAlmostEqual(r1["overall"]["precision"], 0.5)
        self.assertEqual(r1["examples"]["X.sol"]["unexpected"], [("c", "C", "h")])

    def test_missing_example_file_errors(self):
        os.remove(os.path.join(self.examples_dir, "X.sol"))
        with self.assertRaises(corpus.BenchmarkError):
            corpus.run_corpus(self.labels_dir, self.examples_dir, self._fake_analyze)


_BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_BENCH_DIR))
_LABELS = os.path.join(_BENCH_DIR, "labels")
_EXAMPLES = os.path.join(_REPO_ROOT, "examples")
_BASELINE = os.path.join(_BENCH_DIR, "baseline.json")

try:
    from smartgraphical.services import web_api
    _ANALYZE_AVAILABLE = True
except Exception:  # pragma: no cover
    web_api = None
    _ANALYZE_AVAILABLE = False


@unittest.skipUnless(_ANALYZE_AVAILABLE, "web_api not importable")
class RealCorpusTests(unittest.TestCase):
    def setUp(self):
        if not (os.path.isdir(_LABELS) and os.path.isdir(_EXAMPLES)):
            self.skipTest("labels/examples not present")
        self.result = corpus.run_corpus(_LABELS, _EXAMPLES, web_api.analyze_all)

    def test_known_examples_recall(self):
        ex = self.result["examples"]
        self.assertEqual(ex["SimpleAuction.sol"]["recall"], 1.0)
        self.assertEqual(ex["OsTokenRedeemer.sol"]["recall"], 1.0)
        self.assertEqual(self.result["overall"]["recall"], 1.0)

    def test_precision_measured_over_labeled_surface(self):
        ex = self.result["examples"]
        self.assertEqual(ex["SimpleAuction.sol"]["precision"], 0.5)  # 1 TP, 1 labeled FP
        self.assertIsInstance(self.result["overall"]["precision"], float)

    def test_deterministic(self):
        again = corpus.run_corpus(_LABELS, _EXAMPLES, web_api.analyze_all)
        self.assertEqual(self.result, again)


@unittest.skipUnless(_ANALYZE_AVAILABLE, "web_api not importable")
class RecallGuardTests(unittest.TestCase):
    def test_recall_not_below_baseline(self):
        if not os.path.isfile(_BASELINE):
            self.skipTest("no baseline file")
        with open(_BASELINE, encoding="utf-8") as handle:
            baseline = json.load(handle)
        result = corpus.run_corpus(_LABELS, _EXAMPLES, web_api.analyze_all)
        for example, entry in baseline.items():
            if example.startswith("_"):
                continue
            res = result["examples"].get(example)
            self.assertIsNotNone(res, f"baseline example {example} missing from corpus")
            self.assertIsNotNone(res["recall"], f"{example} has no recall")
            self.assertGreaterEqual(
                res["recall"] + 1e-9,
                entry["recall"],
                msg=f"recall regressed for {example}: now-missed {res['missed']}",
            )


if __name__ == "__main__":
    unittest.main()
