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
        self.assertEqual(report["task"], "0")
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

    def test_graph_bundle_tree_manifest_sets_source_file_to_nested_paths(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        contracts_dir = os.path.join(tmp, "contracts")
        os.makedirs(contracts_dir, exist_ok=True)
        a_path = os.path.join(contracts_dir, "A.sol")
        b_path = os.path.join(contracts_dir, "B.sol")
        shutil.copyfile(SOL_FIXTURE, a_path)
        shutil.copyfile(self._mint, b_path)
        with open(a_path, "rb") as fh:
            a_bytes = fh.read()
        with open(b_path, "rb") as fh:
            b_bytes = fh.read()
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "solidity",
            "members": [
                {"path": "contracts/A.sol", "sha256": hashlib.sha256(a_bytes).hexdigest()},
                {"path": "contracts/B.sol", "sha256": hashlib.sha256(b_bytes).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        ms = report["model_summary"]
        members = (ms.get("artifact") or {}).get("bundle_members") or []
        self.assertIn("contracts/A.sol", members)
        self.assertIn("contracts/B.sol", members)
        nodes = (ms.get("graph") or {}).get("nodes") or []
        tags = {n.get("source_file") for n in nodes if n.get("source_file")}
        self.assertIn("contracts/A.sol", tags)
        self.assertIn("contracts/B.sol", tags)

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

    def test_bundle_graph_unresolved_import_creates_external_import_nodes(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        src = (
            "pragma solidity ^0.8.0;\n"
            'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";\n'
            "contract C { }\n"
        )
        path = os.path.join(tmp, "C.sol")
        with open(path, "w", encoding="ascii") as fh:
            fh.write(src)
        digest = hashlib.sha256(src.encode("ascii")).hexdigest()
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [{"path": "C.sol", "sha256": digest}],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        graph = report["model_summary"].get("graph") or {}
        ext = [n for n in graph.get("nodes") or [] if n.get("group") == "external_import"]
        imp_edges = [
            e for e in graph.get("edges") or []
            if e.get("kind") == "import_dependency"
            and "openzeppelin" in str(e.get("label", ""))
        ]
        self.assertTrue(ext, msg="expected external_import nodes for unresolved paths")
        self.assertTrue(imp_edges, msg="expected import_dependency edges to OZ path")

    def test_bundle_graph_inheritance_creates_cross_type_call(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        base_src = (
            "pragma solidity ^0.8.0;\n"
            "contract Base { function f() external {} }\n"
        )
        child_src = (
            "pragma solidity ^0.8.0;\n"
            'import "./Base.sol";\n'
            "contract Child is Base { }\n"
        )
        base_path = os.path.join(tmp, "Base.sol")
        child_path = os.path.join(tmp, "Child.sol")
        with open(base_path, "w", encoding="ascii") as fh:
            fh.write(base_src)
        with open(child_path, "w", encoding="ascii") as fh:
            fh.write(child_src)
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "Base.sol", "sha256": hashlib.sha256(base_src.encode()).hexdigest()},
                {"path": "Child.sol", "sha256": hashlib.sha256(child_src.encode()).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        extends_edges = [
            e for e in edges
            if e.get("kind") == "cross_type_call" and "extends" in str(e.get("label", ""))
        ]
        self.assertTrue(extends_edges, msg=edges)

    def test_bundle_consolidates_local_import_stubs_to_type_nodes(self):
        import hashlib
        import json
        import shutil
        import tempfile

        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        base_src = (
            "pragma solidity ^0.8.0;\n"
            "contract Base { uint256 public x; }\n"
        )
        child_src = (
            "pragma solidity ^0.8.0;\n"
            'import "./Base.sol";\n'
            "contract Child is Base { }\n"
        )
        base_path = os.path.join(tmp, "Base.sol")
        child_path = os.path.join(tmp, "Child.sol")
        with open(base_path, "w", encoding="ascii") as fh:
            fh.write(base_src)
        with open(child_path, "w", encoding="ascii") as fh:
            fh.write(child_src)
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "Base.sol", "sha256": hashlib.sha256(base_src.encode()).hexdigest()},
                {"path": "Child.sol", "sha256": hashlib.sha256(child_src.encode()).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        nodes = (report["model_summary"].get("graph") or {}).get("nodes") or []
        bad = [
            n for n in nodes
            if n.get("group") in ("external", "external_import")
            and n.get("label") == "Base"
        ]
        self.assertEqual(bad, [], msg="in-bundle contract must not stay as external stub")


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


class WebApiBundleIteration4Tests(unittest.TestCase):
    """M5-style bundle edge resolution (duplicate basenames, remaps, Rust super, crate scope)."""

    def test_solidity_bundle_relative_import_picks_same_directory_not_other_token_dir(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        tok_a = "pragma solidity ^0.8.0;\ncontract TokenA { uint256 public x; }\n"
        tok_b = "pragma solidity ^0.8.0;\ncontract TokenB { uint256 public y; }\n"
        usr = (
            "pragma solidity ^0.8.0;\n"
            'import "./Token.sol";\n'
            "contract User { TokenA public t; }\n"
        )
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        ca = os.path.join(tmp, "contracts", "a")
        cb = os.path.join(tmp, "contracts", "b")
        os.makedirs(ca, exist_ok=True)
        os.makedirs(cb, exist_ok=True)
        ta = os.path.join(ca, "Token.sol")
        tb = os.path.join(cb, "Token.sol")
        tu = os.path.join(ca, "User.sol")
        for path, body in ((ta, tok_a), (tb, tok_b), (tu, usr)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        ba = tok_a.encode("ascii")
        bb = tok_b.encode("ascii")
        bu = usr.encode("ascii")
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "solidity",
            "members": [
                {"path": "contracts/a/Token.sol", "sha256": hashlib.sha256(ba).hexdigest()},
                {"path": "contracts/b/Token.sol", "sha256": hashlib.sha256(bb).hexdigest()},
                {"path": "contracts/a/User.sol", "sha256": hashlib.sha256(bu).hexdigest()},
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
        self.assertGreaterEqual(len(bundle_edges), 1, msg=bundle_edges)
        targets = set()
        nodes = (report["model_summary"].get("graph") or {}).get("nodes") or []
        id_to_sf = {str(n.get("id")): n.get("source_file") for n in nodes}
        for e in bundle_edges:
            sf = id_to_sf.get(str(e.get("target")))
            if sf:
                targets.add(sf)
        self.assertIn("contracts/a/Token.sol", targets)
        self.assertNotIn("contracts/b/Token.sol", targets)

    def test_solidity_bundle_unqualified_import_with_two_basenames_skips_edge(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        tok_a = "pragma solidity ^0.8.0;\ncontract TokenA { uint256 public x; }\n"
        tok_b = "pragma solidity ^0.8.0;\ncontract TokenB { uint256 public y; }\n"
        mid = (
            "pragma solidity ^0.8.0;\n"
            'import "Token.sol";\n'
            "contract Mid { }\n"
        )
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        ca = os.path.join(tmp, "contracts", "a")
        cb = os.path.join(tmp, "contracts", "b")
        cm = os.path.join(tmp, "contracts", "m")
        os.makedirs(ca, exist_ok=True)
        os.makedirs(cb, exist_ok=True)
        os.makedirs(cm, exist_ok=True)
        ta = os.path.join(ca, "Token.sol")
        tb = os.path.join(cb, "Token.sol")
        tm = os.path.join(cm, "Mid.sol")
        for path, body in ((ta, tok_a), (tb, tok_b), (tm, mid)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "solidity",
            "members": [
                {"path": "contracts/a/Token.sol", "sha256": hashlib.sha256(tok_a.encode("ascii")).hexdigest()},
                {"path": "contracts/b/Token.sol", "sha256": hashlib.sha256(tok_b.encode("ascii")).hexdigest()},
                {"path": "contracts/m/Mid.sol", "sha256": hashlib.sha256(mid.encode("ascii")).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        ambiguous = [
            e for e in edges
            if e.get("kind") == "bundle_import"
            and e.get("label") == "solidity_import"
            and e.get("import_path") == "Token.sol"
        ]
        self.assertEqual(ambiguous, [], msg="ambiguous basename must not pick a provider")

    def test_solidity_bundle_manifest_remapping_prefix(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        deep = "pragma solidity ^0.8.0;\ncontract Deep { uint256 public z; }\n"
        usr = (
            "pragma solidity ^0.8.0;\n"
            'import "@alias/Deep.sol";\n'
            "contract User { Deep public d; }\n"
        )
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        d_path = os.path.join(tmp, "contracts", "Deep.sol")
        u_path = os.path.join(tmp, "User.sol")
        os.makedirs(os.path.dirname(d_path), exist_ok=True)
        with open(d_path, "w", encoding="ascii") as fh:
            fh.write(deep)
        with open(u_path, "w", encoding="ascii") as fh:
            fh.write(usr)
        bd = deep.encode("ascii")
        bu = usr.encode("ascii")
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "solidity",
            "solidity_remappings": [["@alias/", "contracts/"]],
            "members": [
                {"path": "contracts/Deep.sol", "sha256": hashlib.sha256(bd).hexdigest()},
                {"path": "User.sol", "sha256": hashlib.sha256(bu).hexdigest()},
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

    def test_c_bundle_include_subdir_picks_matching_folder_not_other_unit_h(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        ha = "#ifndef UA\n#define UA\nextern int a;\n#endif\n"
        hb = "#ifndef UB\n#define UB\nextern int b;\n#endif\n"
        c_src = '#include "sub/unit.h"\nstatic void u(void) { (void)a; }\n'
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        da = os.path.join(tmp, "a", "sub")
        db = os.path.join(tmp, "b", "sub")
        os.makedirs(da, exist_ok=True)
        os.makedirs(db, exist_ok=True)
        h_a = os.path.join(da, "unit.h")
        h_b = os.path.join(db, "unit.h")
        c_p = os.path.join(tmp, "a", "user.c")
        os.makedirs(os.path.dirname(c_p), exist_ok=True)
        for path, body in ((h_a, ha), (h_b, hb), (c_p, c_src)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "c",
            "members": [
                {"path": "a/sub/unit.h", "sha256": hashlib.sha256(ha.encode("ascii")).hexdigest()},
                {"path": "b/sub/unit.h", "sha256": hashlib.sha256(hb.encode("ascii")).hexdigest()},
                {"path": "a/user.c", "sha256": hashlib.sha256(c_src.encode("ascii")).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="c")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        inc_edges = [
            e for e in edges
            if e.get("kind") == "tile_to_tile" and e.get("label") == "bundle_member_include"
        ]
        self.assertEqual(len(inc_edges), 1, msg=inc_edges)
        nodes = (report["model_summary"].get("graph") or {}).get("nodes") or []
        id_to_sf = {str(n.get("id")): n.get("source_file") for n in nodes}
        tgt_sf = id_to_sf.get(str(inc_edges[0].get("target")))
        self.assertEqual(tgt_sf, "a/sub/unit.h")

    def test_rust_bundle_super_links_sibling_in_src_before_grandparent(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        root_src = "mod child;\nmod sibling;\n"
        child_src = "use super::sibling;\n#[contractimpl]\npub struct Child;\n"
        sib_src = "#[contractimpl]\npub struct Sibling;\n"
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        sr = os.path.join(tmp, "src", "root.rs")
        sc = os.path.join(tmp, "src", "child.rs")
        ss = os.path.join(tmp, "src", "sibling.rs")
        os.makedirs(os.path.dirname(sr), exist_ok=True)
        for path, body in ((sr, root_src), (sc, child_src), (ss, sib_src)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        br = root_src.encode("ascii")
        bc = child_src.encode("ascii")
        bs = sib_src.encode("ascii")
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "rust",
            "members": [
                {"path": "src/root.rs", "sha256": hashlib.sha256(br).hexdigest()},
                {"path": "src/child.rs", "sha256": hashlib.sha256(bc).hexdigest()},
                {"path": "src/sibling.rs", "sha256": hashlib.sha256(bs).hexdigest()},
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
        self.assertGreaterEqual(len(bundle_edges), 1, msg=bundle_edges)

    def test_rust_bundle_crate_use_respects_src_lib_root(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        lib = "mod helper;\n"
        helper = "#[contractimpl]\npub struct Helper;\n"
        user = "use crate::helper;\n#[contractimpl]\npub struct User;\n"
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        lp = os.path.join(tmp, "src", "lib.rs")
        hp = os.path.join(tmp, "src", "helper.rs")
        up = os.path.join(tmp, "src", "user.rs")
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        for path, body in ((lp, lib), (hp, helper), (up, user)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        bl = lib.encode("ascii")
        bh = helper.encode("ascii")
        bu = user.encode("ascii")
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "rust",
            "members": [
                {"path": "src/lib.rs", "sha256": hashlib.sha256(bl).hexdigest()},
                {"path": "src/helper.rs", "sha256": hashlib.sha256(bh).hexdigest()},
                {"path": "src/user.rs", "sha256": hashlib.sha256(bu).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="rust")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        mod_edges = [
            e for e in edges
            if e.get("kind") == "bundle_import" and e.get("label") == "rust_module"
        ]
        self.assertGreaterEqual(len(mod_edges), 1, msg=mod_edges)

    def test_rust_bundle_inline_mod_nested_mod_decl_resolves(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        lib = (
            "mod pool {\n"
            "    mod logic;\n"
            "}\n"
            "#[contractimpl]\n"
            "pub struct Root;\n"
        )
        logic = "#[contractimpl]\npub struct Logic;\n"
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        lp = os.path.join(tmp, "src", "lib.rs")
        lg = os.path.join(tmp, "src", "pool", "logic.rs")
        os.makedirs(os.path.dirname(lg), exist_ok=True)
        for path, body in ((lp, lib), (lg, logic)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        bl = lib.encode("ascii")
        blogic = logic.encode("ascii")
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "rust",
            "members": [
                {"path": "src/lib.rs", "sha256": hashlib.sha256(bl).hexdigest()},
                {"path": "src/pool/logic.rs", "sha256": hashlib.sha256(blogic).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="rust")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        want = [
            e for e in edges
            if e.get("kind") == "bundle_import"
            and e.get("label") == "rust_module"
            and e.get("module_ref") == "logic"
        ]
        self.assertEqual(len(want), 1, msg=edges)
        nodes = (report["model_summary"].get("graph") or {}).get("nodes") or []
        id_to_sf = {str(n.get("id")): n.get("source_file") for n in nodes}
        self.assertEqual(id_to_sf.get(str(want[0].get("target"))), "src/pool/logic.rs")

    def test_c_bundle_c_include_prefixes_resolves_vendor_path(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        h_src = "#ifndef VH\n#define VH\nextern int v;\n#endif\n"
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        hp = os.path.join(tmp, "vendor", "common", "x.h")
        cp = os.path.join(tmp, "src", "app.c")
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        os.makedirs(os.path.dirname(cp), exist_ok=True)
        with open(hp, "w", encoding="ascii") as fh:
            fh.write(h_src)
        c_body = b'#include "common/x.h"\nstatic void u(void) { (void)v; }\n'
        with open(cp, "wb") as fh:
            fh.write(c_body)
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "c",
            "c_include_prefixes": ["vendor"],
            "members": [
                {"path": "vendor/common/x.h", "sha256": hashlib.sha256(h_src.encode("ascii")).hexdigest()},
                {"path": "src/app.c", "sha256": hashlib.sha256(c_body).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="c")
        self.assertEqual(report["status"], "ok")
        edges = (report["model_summary"].get("graph") or {}).get("edges") or []
        inc_edges = [
            e for e in edges
            if e.get("kind") == "tile_to_tile" and e.get("label") == "bundle_member_include"
        ]
        self.assertEqual(len(inc_edges), 1, msg=inc_edges)

    def test_solidity_bundle_import_hidden_in_block_comment_is_ignored(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        lib = "pragma solidity ^0.8.0;\ncontract Lib { uint256 public x; }\n"
        usr = (
            "pragma solidity ^0.8.0;\n"
            "/* import \"./Ghost.sol\"; */\n"
            'import "./Lib.sol";\n'
            "contract User { Lib public t; }\n"
        )
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        lp = os.path.join(tmp, "Lib.sol")
        up = os.path.join(tmp, "User.sol")
        with open(lp, "w", encoding="ascii") as fh:
            fh.write(lib)
        with open(up, "w", encoding="ascii") as fh:
            fh.write(usr)
        bl = lib.encode("ascii")
        bu = usr.encode("ascii")
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "Lib.sol", "sha256": hashlib.sha256(bl).hexdigest()},
                {"path": "User.sol", "sha256": hashlib.sha256(bu).hexdigest()},
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
        self.assertEqual(bundle_edges[0].get("import_path"), "./Lib.sol")

    def test_solidity_bundle_graph_has_bundle_edge_resolution_hints_on_ambiguous(self):
        import hashlib
        import json
        import os
        import shutil
        import tempfile

        tok_a = "pragma solidity ^0.8.0;\ncontract TokenA { uint256 public x; }\n"
        tok_b = "pragma solidity ^0.8.0;\ncontract TokenB { uint256 public y; }\n"
        mid = 'pragma solidity ^0.8.0;\nimport "Token.sol";\ncontract Mid { }\n'
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        os.makedirs(os.path.join(tmp, "a"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "b"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "m"), exist_ok=True)
        for path, body in (
            (os.path.join(tmp, "a", "Token.sol"), tok_a),
            (os.path.join(tmp, "b", "Token.sol"), tok_b),
            (os.path.join(tmp, "m", "Mid.sol"), mid),
        ):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        manifest = {
            "version": 2,
            "layout": "tree",
            "language": "solidity",
            "members": [
                {"path": "a/Token.sol", "sha256": hashlib.sha256(tok_a.encode("ascii")).hexdigest()},
                {"path": "b/Token.sol", "sha256": hashlib.sha256(tok_b.encode("ascii")).hexdigest()},
                {"path": "m/Mid.sol", "sha256": hashlib.sha256(mid.encode("ascii")).hexdigest()},
            ],
        }
        with open(os.path.join(tmp, "sg_bundle_manifest.json"), "w", encoding="ascii") as fh:
            json.dump(manifest, fh)

        report = web_api.graph(tmp, language="solidity")
        self.assertEqual(report["status"], "ok")
        hints = (report["model_summary"].get("graph") or {}).get("exploration_hints") or {}
        ber = hints.get("bundle_edge_resolution") or {}
        self.assertGreaterEqual(ber.get("skipped_solidity_ambiguous_basename", 0), 1)


class WebApiRustModuleLinksTests(unittest.TestCase):
    """Inline mod nesting for Rust file-module declarations (C3)."""

    def test_collect_module_links_inline_stack(self):
        src = "mod p { mod a; mod q { mod b; } }\n"
        refs = web_api._rust_collect_module_links(src)
        mods = [(k, n, p) for k, n, p in refs if k == "mod"]
        self.assertIn(("mod", "a", ("p",)), mods)
        self.assertIn(("mod", "b", ("p", "q")), mods)


class WebApiSolidityImportPathsTests(unittest.TestCase):
    """_solidity_file_import_paths: A3 normalization (line comments, spacing, braced from)."""

    def test_import_line_comment_after_statement_is_ignored(self):
        src = (
            'pragma solidity ^0.8.0;\n'
            'import "./Lib.sol"; // uses Lib\n'
            "contract C {}\n"
        )
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./Lib.sol"])

    def test_import_line_comment_semicolon_slash_slash_no_space(self):
        src = 'import "./Lib.sol";//uses\n'
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./Lib.sol"])

    def test_double_slash_inside_quoted_path_is_not_line_comment(self):
        src = 'import "./a//b.sol";\n'
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./a//b.sol"])

    def test_braced_import_extra_whitespace(self):
        src = 'import  {  X  ,  Y  }  from  "./Lib.sol"  ;\n'
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./Lib.sol"])

    def test_braced_import_multiline(self):
        src = (
            "import {\n    IX\n} from \"./Pair.sol\";\n"
        )
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./Pair.sol"])

    def test_import_star_from_with_line_comment(self):
        src = 'import * as T from "./Types.sol"; // re-export\n'
        self.assertEqual(web_api._solidity_file_import_paths(src), ["./Types.sol"])

    def test_solidity_bundle_import_with_trailing_line_comment_resolves(self):
        import hashlib
        import json
        import shutil
        import tempfile

        lib = "pragma solidity ^0.8.0;\ncontract Lib { uint256 public x; }\n"
        usr = (
            "pragma solidity ^0.8.0;\n"
            'import "./Lib.sol"; // dependency: Lib\n'
            "contract User { Lib public t; }\n"
        )
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        lp = os.path.join(tmp, "Lib.sol")
        up = os.path.join(tmp, "User.sol")
        for path, body in ((lp, lib), (up, usr)):
            with open(path, "w", encoding="ascii") as fh:
                fh.write(body)
        bl = lib.encode("ascii")
        bu = usr.encode("ascii")
        manifest = {
            "version": 1,
            "language": "solidity",
            "members": [
                {"path": "Lib.sol", "sha256": hashlib.sha256(bl).hexdigest()},
                {"path": "User.sol", "sha256": hashlib.sha256(bu).hexdigest()},
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
        self.assertEqual(bundle_edges[0].get("import_path"), "./Lib.sol")


class WebApiAnalyzeCTests(unittest.TestCase):
    """web_api facade on checked-in .c fixtures."""

    def setUp(self):
        _require_fixture(C_FIXTURE)

    def test_analyze_c_task(self):
        report = web_api.analyze(C_FIXTURE, "1", language="c", mode="auditor")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["language"], "c")
        self.assertEqual(report["task"], "1")
        self.assertIsInstance(report["findings"], list)

    def test_analyze_c_auto_detects_from_extension(self):
        report = web_api.analyze(C_FIXTURE, "1")
        self.assertEqual(report["language"], "c")

    def test_analyze_all_c(self):
        report = web_api.analyze_all(C_FIXTURE, language="c")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["task"], "0")
        self.assertIn("1", report["rules_run"])
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
        self.assertEqual(ids[0], "0")
        meta_task = payload["tasks"][0]
        self.assertEqual(meta_task["kind"], "meta")
        rule_task = next(task for task in payload["tasks"] if task["id"] == "11")
        self.assertEqual(rule_task["kind"], "rule")
        self.assertTrue(rule_task["title"])

    def test_list_tasks_returns_c_catalog(self):
        payload = web_api.list_tasks("c")
        self.assertEqual(payload["language"], "c")
        ids = [task["id"] for task in payload["tasks"]]
        self.assertIn("1", ids)
        self.assertEqual(ids[0], "0")

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
