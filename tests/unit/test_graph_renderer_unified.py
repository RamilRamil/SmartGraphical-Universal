"""Feature 017: the CLI graphviz renderer draws the SAME canonical projection the
web cytoscape view uses, so the two pillars cannot drift (Constitution V).

These tests do not require graphviz to be installed: a fake Digraph records what
``GraphBuilder.render`` would draw, and the parity assertion compares that against
``serializers.model_graph_to_dict``.
"""
import contextlib
import io
import os
import unittest
from copy import deepcopy

import smartgraphical.core.graph as graph_module
from smartgraphical.core.graph import GraphBuilder, _plan_render, COMPOUND_GROUPS
from smartgraphical.services.analysis_service import AnalysisService
from smartgraphical.services.serializers import model_graph_to_dict
from smartgraphical.adapters.c_base.adapter import CBaseAdapterV0
from smartgraphical.adapters.rust_stellar.adapter import RustStellarAdapterV0

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _model(rel, adapter=None):
    path = os.path.join(REPO_ROOT, rel)
    service = AnalysisService(adapter=adapter) if adapter else AnalysisService()
    return service.analyze(path).normalized_model


def _make_fake_graphviz(recorder):
    class _FakeGraph:
        def __init__(self, *a, **k):
            pass

        def attr(self, *a, **k):
            pass

        def node(self, nid, label=None, **k):
            recorder["nodes"].append(nid)

        def edge(self, source, target, **k):
            recorder["edges"].append((source, target))

        def subgraph(self, name=None):
            @contextlib.contextmanager
            def _cm():
                yield _FakeGraph()  # writes funnel to the same recorder
            return _cm()

        def render(self, *a, **k):
            recorder["rendered"] = True

    class _FakeGraphviz:
        Digraph = _FakeGraph

    return _FakeGraphviz()


def _drawn_via_render(model):
    recorder = {"nodes": [], "edges": [], "rendered": False}
    original = graph_module.graphviz
    graph_module.graphviz = _make_fake_graphviz(recorder)
    try:
        GraphBuilder().render(model, "x")
    finally:
        graph_module.graphviz = original
    return recorder


FIXTURES = [
    ("tests/fixtures/solidity/WithdrawNoGuard.sol", None),
    ("tests/fixtures/c/MinimalIncludeTu.c", CBaseAdapterV0()),
    ("tests/fixtures/rust/SorobanViolations.rs", RustStellarAdapterV0()),
]


class RendererParityTests(unittest.TestCase):
    def test_drawn_node_ids_match_canonical_projection(self):
        for rel, adapter in FIXTURES:
            with self.subTest(fixture=rel):
                model = _model(rel, adapter)
                canonical = model_graph_to_dict(model)
                canonical_ids = {str(n.get("id", "")) for n in canonical["nodes"]}
                compound_ids = {
                    str(n.get("id", ""))
                    for n in canonical["nodes"]
                    if str(n.get("group", "")) in COMPOUND_GROUPS
                }
                rec = _drawn_via_render(model)
                drawn = set(rec["nodes"])
                # clusters (compound nodes) are containers, not drawn leaf nodes;
                # every other canonical node id must be drawn exactly once.
                self.assertEqual(drawn, canonical_ids - compound_ids)
                # and the union of drawn + cluster ids reconstructs the full set
                self.assertEqual(drawn | compound_ids, canonical_ids)

    def test_drawn_edges_match_canonical_projection(self):
        for rel, adapter in FIXTURES:
            with self.subTest(fixture=rel):
                model = _model(rel, adapter)
                canonical = model_graph_to_dict(model)
                expected = {
                    (str(e.get("source", "")), str(e.get("target", "")))
                    for e in canonical["edges"]
                }
                rec = _drawn_via_render(model)
                self.assertEqual(set(rec["edges"]), expected)

    def test_plan_render_partitions_compound_and_children(self):
        model = _model("tests/fixtures/solidity/WithdrawNoGuard.sol")
        clusters, top_nodes, edges = _plan_render(model_graph_to_dict(model))
        # every clustered child carries the cluster id as its parent
        for cid, info in clusters.items():
            for child in info["children"]:
                self.assertEqual(str(child.get("parent", "")), cid)
        # top-level nodes are not compound and have no in-bundle parent cluster
        for n in top_nodes:
            self.assertNotIn(str(n.get("group", "")), COMPOUND_GROUPS)


class RendererGracefulTests(unittest.TestCase):
    def test_render_without_graphviz_does_not_raise(self):
        model = _model("tests/fixtures/solidity/WithdrawNoGuard.sol")
        original = graph_module.graphviz
        graph_module.graphviz = None
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                result = GraphBuilder().render(model, "x")
        finally:
            graph_module.graphviz = original
        self.assertIsNone(result)
        self.assertIn("graphviz", buf.getvalue().lower())

    def test_render_does_not_mutate_canonical_projection(self):
        model = _model("tests/fixtures/c/MinimalIncludeTu.c", CBaseAdapterV0())
        before = deepcopy(model_graph_to_dict(model))
        _drawn_via_render(model)
        after = model_graph_to_dict(model)
        self.assertEqual(before, after)


class RendererRealGraphvizSmokeTests(unittest.TestCase):
    def test_real_render_emits_artifact_when_available(self):
        if graph_module.graphviz is None:
            self.skipTest("graphviz not installed")
        import tempfile
        model = _model("tests/fixtures/solidity/WithdrawNoGuard.sol")
        with tempfile.TemporaryDirectory() as tmp:
            label = os.path.join(tmp, "g")
            GraphBuilder().render(model, label)  # must not raise


if __name__ == "__main__":
    unittest.main()
