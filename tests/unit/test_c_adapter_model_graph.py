"""C adapter: normalized model graph inputs (call edges, structs)."""
import os
import unittest
from unittest.mock import patch

import smartgraphical.services.serializers as serializers_module

from smartgraphical.adapters.c_base.adapter import (
    CBaseAdapterV0,
    build_normalized_model,
)
from smartgraphical.services.serializers import model_graph_to_dict


TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_C = os.path.join(TESTS_DIR, "fixtures", "c")


def _fixture(name):
    path = os.path.join(FIXTURE_C, name)
    if not os.path.isfile(path):
        raise AssertionError(f"missing {path}")
    return path


class CAdapterCallGraphTests(unittest.TestCase):

    def test_minimal_tu_has_internal_call_edge(self):
        path = _fixture("MinimalTu.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        kinds = {(e.source_name, e.target_name) for e in model.call_edges}
        self.assertIn(("public_add", "internal_dup"), kinds)

    def test_minimal_struct_tu_has_struct_and_call_edge(self):
        path = _fixture("MinimalStructTu.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        names = {e.name for e in model.types[0].state_entities}
        self.assertEqual(names, {"Widget"})
        kinds = {(e.source_name, e.target_name) for e in model.call_edges}
        self.assertIn(("widget_sum", "getv"), kinds)

    def test_minimal_struct_tu_has_struct_use_workspace_edges(self):
        path = _fixture("MinimalStructTu.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        ws = [
            e for e in model.call_edges
            if e.edge_kind == "function_to_workspace"
        ]
        self.assertTrue(ws)
        targets = {(e.source_name, e.target_name) for e in ws}
        self.assertIn(("getv", "Widget"), targets)
        self.assertIn(("widget_sum", "Widget"), targets)
        getv_key = "MinimalStructTu.getv"
        hints = model.findings_data.function_facts[getv_key].get(
            "struct_field_access_hints", [],
        )
        self.assertTrue(
            any(h["struct"] == "Widget" and h["field"] == "v" for h in hints),
        )

    def test_typedef_struct_alias_and_field_hints(self):
        src = """
typedef struct { int x; } BoxAlias;
typedef struct Named { int x; } NamedAlias;

static void bump(BoxAlias * b) { b->x = 1; }
static void named(NamedAlias * p) { (void)p->x; }
"""
        model = build_normalized_model("tu.c", src)
        kinds = {e.name: e.kind for e in model.types[0].state_entities}
        self.assertEqual(kinds.get("BoxAlias"), "typedef_struct")
        self.assertEqual(kinds.get("Named"), "struct")
        self.assertEqual(kinds.get("NamedAlias"), "typedef_struct")
        ws = {(e.source_name, e.target_name) for e in model.call_edges
              if e.edge_kind == "function_to_workspace"}
        self.assertIn(("bump", "BoxAlias"), ws)
        self.assertIn(("named", "NamedAlias"), ws)
        bh = model.findings_data.function_facts["tu.bump"].get(
            "struct_field_access_hints", [])
        self.assertTrue(
            any(h["struct"] == "BoxAlias" and h["field"] == "x" for h in bh),
        )

    def test_unsigned_int_star_no_phantom_struct_int_edge(self):
        src = """
void f(unsigned int * p) { (void)p; }
"""
        model = build_normalized_model("tu.c", src)
        ws = [e for e in model.call_edges if e.edge_kind == "function_to_workspace"]
        targets = {e.target_name for e in ws}
        self.assertNotIn("int", targets)

    def test_minimal_include_tu_discovers_inc_workspace_node(self):
        path = _fixture("MinimalIncludeTu.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        kinds = {e.kind for e in model.types[0].state_entities}
        self.assertIn("include_template", kinds)
        inc = next(
            e for e in model.types[0].state_entities
            if e.kind == "include_template"
        )
        self.assertTrue(inc.name.startswith("inc:"))
        self.assertIn("fd_pool.c", inc.name)
        inc_edges = [
            e for e in model.call_edges
            if e.edge_kind == "function_to_include_template"
        ]
        self.assertEqual(len(inc_edges), 1)
        self.assertEqual(inc_edges[0].source_name, "__tu_include_anchor__")
        graph = model_graph_to_dict(model)
        tile_id = next(n["id"] for n in graph["nodes"] if n.get("group") == "tile")
        inc_edges_json = [
            e for e in graph["edges"]
            if e.get("kind") == "function_to_include_template"
        ]
        self.assertEqual(len(inc_edges_json), 1)
        self.assertEqual(inc_edges_json[0]["source"], tile_id)
        self.assertTrue(
            any(
                "fd_pool.c" in e["target"]
                for e in inc_edges_json
            ),
        )
        self.assertEqual(inc_edges[0].target_name, inc.name)

    def test_minimal_include_angle_bracket(self):
        path = _fixture("MinimalIncludeAngleTu.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        inc = next(
            e for e in model.types[0].state_entities
            if e.kind == "include_template"
        )
        self.assertIn("stub_tmpl.c", inc.name)
        self.assertTrue(inc.raw_signature.startswith("#include <"))

    def test_minimal_include_dup_basename_disambiguated(self):
        path = _fixture("MinimalIncludeDupBasename.c")
        with open(path, "r", errors="replace") as f:
            model = build_normalized_model(path, f.read())
        inc_names = [
            e.name for e in model.types[0].state_entities
            if e.kind == "include_template"
        ]
        self.assertEqual(len(inc_names), 2)
        self.assertIn("inc:pool.c", inc_names)
        self.assertTrue(any(n.startswith("inc:pool.c~") for n in inc_names))
        inc_edge_n = sum(
            1 for e in model.call_edges
            if e.edge_kind == "function_to_include_template"
        )
        self.assertEqual(inc_edge_n, 2)


class CGraphSerializerHintsTests(unittest.TestCase):

    def test_c_graph_payload_includes_exploration_hints(self):
        ctx = CBaseAdapterV0().parse_source(_fixture("MinimalTu.c"))
        graph = model_graph_to_dict(ctx.normalized_model)
        self.assertIn("exploration_hints", graph)
        h = graph["exploration_hints"]
        self.assertTrue(h.get("call_edges_are_heuristic"))
        self.assertGreaterEqual(h.get("call_edge_count", 0), 1)
        self.assertGreaterEqual(h.get("edge_count", 0), 1)
        self.assertGreaterEqual(h.get("node_count", 0), 1)
        self.assertNotIn("large_graph_warning", h)
        self.assertIn("note", h)

    def test_c_graph_edges_are_heuristic_confidence(self):
        ctx = CBaseAdapterV0().parse_source(_fixture("MinimalTu.c"))
        graph = model_graph_to_dict(ctx.normalized_model)
        internal_edges = [
            e for e in graph["edges"]
            if e.get("kind") == "function_to_function"
        ]
        self.assertTrue(internal_edges)
        for e in internal_edges:
            self.assertTrue(e.get("is_heuristic"))
            self.assertEqual(e.get("confidence"), "heuristic")

    def test_c_graph_struct_use_edges_canonical_kind(self):
        ctx = CBaseAdapterV0().parse_source(_fixture("MinimalStructTu.c"))
        graph = model_graph_to_dict(ctx.normalized_model)
        ws_edges = [e for e in graph["edges"] if e.get("kind") == "function_to_workspace"]
        self.assertTrue(ws_edges)
        for e in ws_edges:
            self.assertTrue(e.get("is_heuristic"))

    def test_c_graph_include_template_edges(self):
        ctx = CBaseAdapterV0().parse_source(_fixture("MinimalIncludeTu.c"))
        graph = model_graph_to_dict(ctx.normalized_model)
        inc_edges = [
            e for e in graph["edges"]
            if e.get("kind") == "function_to_include_template"
        ]
        self.assertTrue(inc_edges)
        for e in inc_edges:
            self.assertTrue(e.get("is_heuristic"))
        fn = next(n for n in graph["nodes"] if n.get("label") == "use_template_marker")
        self.assertTrue(fn.get("calls_include_template"))


class CGraphPhaseCTests(unittest.TestCase):

    def test_c_graph_external_unresolved_classes_by_prefix(self):
        src = """
void sink(void) {}
void mainfn(void) {
  fd_sha256_ref(0);
  SYS_halt();
  __NR_read();
  pthread_mutex_lock(0);
  epoll_wait(0, 0, 0, 0);
  ioctl(0, 0);
  plain_sym();
}
"""
        model = build_normalized_model("tu.c", src)
        graph = model_graph_to_dict(model)
        ext_ids = {n["id"] for n in graph["nodes"] if n.get("group") == "external"}
        self.assertIn("external:unresolved_lib:fd_sha256_ref", ext_ids)
        self.assertIn("external:unresolved_syscall:SYS_halt", ext_ids)
        self.assertIn("external:unresolved_syscall:__NR_read", ext_ids)
        self.assertIn("external:unresolved_lib:pthread_mutex_lock", ext_ids)
        self.assertIn("external:unresolved_lib:epoll_wait", ext_ids)
        self.assertIn("external:unresolved_lib:ioctl", ext_ids)
        self.assertIn("external:unresolved_symbol:plain_sym", ext_ids)

    def test_c_graph_function_node_has_ordered_callees(self):
        src = """
void tail(void) {}
void head(void) { tail(); fd_read(); tail(); }
"""
        model = build_normalized_model("tu.c", src)
        graph = model_graph_to_dict(model)
        head = next(n for n in graph["nodes"] if n.get("label") == "head")
        self.assertEqual(
            head.get("heuristic_callees_ordered"),
            ["tail", "fd_read", "tail"],
        )

    def test_c_exploration_hints_large_graph_warning(self):
        lines = ["void z(void) {}"]
        lines.extend(f"void f{i}(void) {{}}" for i in range(6))
        src = "\n".join(lines)
        model = build_normalized_model("bigtu.c", src)
        with patch.object(serializers_module, "C_GRAPH_NODE_WARN_THRESHOLD", 5):
            graph = model_graph_to_dict(model)
        h = graph["exploration_hints"]
        self.assertTrue(h.get("large_graph_warning"))
        self.assertIn("large_graph_note", h)


if __name__ == "__main__":
    unittest.main()
