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
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "MinimalGuard.sol")
C_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "c", "MinimalTu.c")


def _require_fixture(path):
    if not os.path.isfile(path):
        raise unittest.SkipTest(f"fixture missing: {path}")


class WebApiHealthTests(unittest.TestCase):

    def test_health_returns_stable_shape(self):
        report = web_api.health()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["service"], "smartgraphical")
        self.assertIn("solidity", report["supported_languages"])
        self.assertIn("c", report["supported_languages"])
        self.assertIn("rust", report["supported_languages"])
        self.assertIn("auditor", report["supported_modes"])


class WebApiAnalyzeTests(unittest.TestCase):

    def setUp(self):
        _require_fixture(SOL_FIXTURE)

    def test_analyze_returns_findings_for_known_task(self):
        report = web_api.analyze(SOL_FIXTURE, "11", language="solidity", mode="auditor")
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
        report = web_api.analyze(SOL_FIXTURE, "11")
        self.assertEqual(report["language"], "solidity")

    def test_analyze_rejects_missing_path(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze("__missing__.sol", "11")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PATH)

    def test_analyze_rejects_invalid_mode(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SOL_FIXTURE, "11", language="solidity", mode="bad")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_MODE)

    def test_analyze_rejects_invalid_language(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SOL_FIXTURE, "11", language="go")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_LANGUAGE)

    def test_analyze_rejects_unknown_task(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SOL_FIXTURE, "999", language="solidity")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_TASK)

    def test_analyze_rejects_empty_task(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze(SOL_FIXTURE, "   ", language="solidity")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_TASK)


class WebApiAnalyzeAllTests(unittest.TestCase):

    def setUp(self):
        _require_fixture(SOL_FIXTURE)

    def test_analyze_all_runs_every_rule(self):
        report = web_api.analyze_all(SOL_FIXTURE, language="solidity")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["task"], "all")
        self.assertGreater(len(report["rules_run"]), 1)
        self.assertEqual(report["findings_count"], len(report["findings"]))

    def test_analyze_all_rejects_missing_path(self):
        with self.assertRaises(WebApiError) as ctx:
            web_api.analyze_all("__missing__.sol")
        self.assertEqual(ctx.exception.code, ERROR_INVALID_PATH)


class WebApiGraphTests(unittest.TestCase):

    def setUp(self):
        _require_fixture(SOL_FIXTURE)

    def test_graph_returns_model_summary(self):
        report = web_api.graph(SOL_FIXTURE, language="solidity")
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


class WebApiBundleGraphTests(unittest.TestCase):

    def setUp(self):
        _require_fixture(SOL_FIXTURE)
        self._mint = os.path.join(
            REPO_ROOT, "tests", "fixtures", "solidity", "ExternalMint.sol",
        )
        if not os.path.isfile(self._mint):
            raise unittest.SkipTest(f"fixture missing: {self._mint}")

    def test_graph_bundle_merges_two_files(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        a_path = os.path.join(tmp, "A.sol")
        b_path = os.path.join(tmp, "ExternalMint.sol")
        shutil.copyfile(SOL_FIXTURE, a_path)
        shutil.copyfile(self._mint, b_path)
        with open(a_path, "rb") as fh:
            a_bytes = fh.read()
        with open(b_path, "rb") as fh:
            b_bytes = fh.read()
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "A.sol", "sha256": hashlib.sha256(a_bytes).hexdigest()},
                {"path": "ExternalMint.sol", "sha256": hashlib.sha256(b_bytes).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        ms = report["model_summary"]
        self.assertIn("bundle_members", (ms.get("artifact") or {}))
        nodes = (ms.get("graph") or {}).get("nodes") or []
        tags = {n.get("source_file") for n in nodes if n.get("source_file")}
        self.assertIn("A.sol", tags)
        self.assertIn("ExternalMint.sol", tags)

    def test_analyze_all_bundle_tags_findings(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        a_path = os.path.join(tmp, "A.sol")
        b_path = os.path.join(tmp, "ExternalMint.sol")
        shutil.copyfile(SOL_FIXTURE, a_path)
        shutil.copyfile(self._mint, b_path)
        with open(a_path, "rb") as fh:
            a_bytes = fh.read()
        with open(b_path, "rb") as fh:
            b_bytes = fh.read()
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "A.sol", "sha256": hashlib.sha256(a_bytes).hexdigest()},
                {"path": "ExternalMint.sol", "sha256": hashlib.sha256(b_bytes).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        report = web_api.analyze_all(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        self.assertGreater(len(report["findings"]), 0)
        for row in report["findings"]:
            self.assertIn("source_file", row)


class WebApiCBundleIncludeTests(unittest.TestCase):

    def test_bundle_graph_links_included_header(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        user_c = os.path.join(tmp, "user.c")
        dep_h = os.path.join(tmp, "dep.h")
        with open(user_c, "w", encoding="ascii") as fh:
            fh.write('#include "dep.h"\nstatic void u(void) { (void)0; }\n')
        with open(dep_h, "w", encoding="ascii") as fh:
            fh.write("#ifndef DEP_H\n#define DEP_H\n#endif\n")
        with open(user_c, "rb") as fh:
            ub = fh.read()
        with open(dep_h, "rb") as fh:
            hb = fh.read()
        manifest = {
            "version": 1,
            "language": "c",
            "members": [
                {"path": "dep.h", "sha256": hashlib.sha256(hb).hexdigest()},
                {"path": "user.c", "sha256": hashlib.sha256(ub).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="c")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        bundle_edges = [
            e for e in edges
            if e.get("kind") == "tile_to_tile" and e.get("label") == "bundle_member_include"
        ]
        self.assertEqual(len(bundle_edges), 1, msg=bundle_edges)


class WebApiSolidityBundleImportTests(unittest.TestCase):

    def test_bundle_graph_import_edge_between_sol_files(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        lib_p = os.path.join(tmp, "Lib.sol")
        usr_p = os.path.join(tmp, "User.sol")
        lib_src = (
            "pragma solidity ^0.8.0;\n"
            "contract Lib { uint256 public x; }\n"
        )
        usr_src = (
            "pragma solidity ^0.8.0;\n"
            'import "./Lib.sol";\n'
            "contract User { Lib public t; }\n"
        )
        with open(lib_p, "w", encoding="ascii") as fh:
            fh.write(lib_src)
        with open(usr_p, "w", encoding="ascii") as fh:
            fh.write(usr_src)
        lb = lib_src.encode("ascii")
        ub = usr_src.encode("ascii")
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "Lib.sol", "sha256": hashlib.sha256(lb).hexdigest()},
                {"path": "User.sol", "sha256": hashlib.sha256(ub).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        bundle_edges = [
            e for e in edges
            if e.get("kind") == "bundle_import" and e.get("label") == "solidity_import"
        ]
        self.assertEqual(len(bundle_edges), 1, msg=bundle_edges)


class WebApiRustBundleModuleTests(unittest.TestCase):

    def test_bundle_graph_mod_edge_between_rs_files(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        root_p = os.path.join(tmp, "root.rs")
        bar_p = os.path.join(tmp, "bar.rs")
        bar_src = (
            "#[contractimpl]\n"
            "pub struct Bar;\n"
            "impl Bar { pub fn baz() {} }\n"
        )
        root_src = "mod bar;\n"
        with open(bar_p, "w", encoding="ascii") as fh:
            fh.write(bar_src)
        with open(root_p, "w", encoding="ascii") as fh:
            fh.write(root_src)
        rb = bar_src.encode("ascii")
        rr = root_src.encode("ascii")
        manifest = {
            "version": 1,
            "language": "rust",
            "members": [
                {"path": "bar.rs", "sha256": hashlib.sha256(rb).hexdigest()},
                {"path": "root.rs", "sha256": hashlib.sha256(rr).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="rust")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        bundle_edges = [
            e for e in edges
            if e.get("kind") == "bundle_import" and e.get("label") == "rust_module"
        ]
        self.assertEqual(len(bundle_edges), 1, msg=bundle_edges)


class WebApiAnalyzeCTests(unittest.TestCase):
    """web_api facade on checked-in .c fixtures."""

    def setUp(self):
        _require_fixture(C_FIXTURE)

    def test_analyze_c_task(self):
        report = web_api.analyze(C_FIXTURE, "101", language="c", mode="auditor")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "c")
        self.assertEqual(report["task"], "101")
        self.assertIsInstance(report["findings"], list)

    def test_analyze_c_auto_detects_from_extension(self):
        report = web_api.analyze(C_FIXTURE, "101")
        self.assertEqual(report["language"], "c")

    def test_analyze_all_c(self):
        report = web_api.analyze_all(C_FIXTURE, language="c")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["task"], "all")
        self.assertIn("101", report["rules_run"])
        self.assertEqual(report["findings_count"], len(report["findings"]))

    def test_graph_c(self):
        report = web_api.graph(C_FIXTURE, language="c")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "c")
        summary = report["model_summary"]
        self.assertGreaterEqual(summary["functions_count"], 1)


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
            web_api.list_tasks("go")
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
