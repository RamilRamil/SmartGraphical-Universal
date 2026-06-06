"""Pure-diff unit tests for feature 018 (smartgraphical/services/graph_diff.py)."""
import unittest

from smartgraphical.services.graph_diff import diff_graph_payloads


def _payload(nodes, edges):
    return {"model_summary": {"graph": {"nodes": nodes, "edges": edges}}}


def _node(nid, group="function", label="", kind=""):
    return {"id": nid, "group": group, "label": label or nid, "kind": kind}


def _edge(source, target, kind, eid="edge:0", label=""):
    return {"id": eid, "source": source, "target": target, "kind": kind, "label": label}


class GraphDiffNodeTests(unittest.TestCase):
    def test_added_node(self):
        a = _payload([_node("function:C.f")], [])
        b = _payload([_node("function:C.f"), _node("function:C.g")], [])
        d = diff_graph_payloads(a, b)
        self.assertEqual([n["id"] for n in d["added_nodes"]], ["function:C.g"])
        self.assertEqual(d["removed_nodes"], [])
        self.assertEqual(d["changed_nodes"], [])
        self.assertEqual(d["added_node_count"], 1)

    def test_removed_node(self):
        a = _payload([_node("function:C.f"), _node("state:C.x", group="state")], [])
        b = _payload([_node("function:C.f")], [])
        d = diff_graph_payloads(a, b)
        self.assertEqual([n["id"] for n in d["removed_nodes"]], ["state:C.x"])
        self.assertEqual(d["added_nodes"], [])

    def test_changed_node_carries_before_after(self):
        a = _payload([_node("function:C.f", label="foo", kind="public")], [])
        b = _payload([_node("function:C.f", label="bar", kind="public")], [])
        d = diff_graph_payloads(a, b)
        self.assertEqual(d["added_nodes"], [])
        self.assertEqual(d["removed_nodes"], [])
        self.assertEqual(len(d["changed_nodes"]), 1)
        ch = d["changed_nodes"][0]
        self.assertEqual(ch["id"], "function:C.f")
        self.assertEqual(ch["before"]["label"], "foo")
        self.assertEqual(ch["after"]["label"], "bar")

    def test_identical_graphs_yield_no_changes(self):
        nodes = [_node("function:C.f"), _node("type:C", group="type")]
        a = _payload(nodes, [])
        b = _payload([dict(n) for n in nodes], [])
        d = diff_graph_payloads(a, b)
        self.assertEqual(d["added_nodes"], [])
        self.assertEqual(d["removed_nodes"], [])
        self.assertEqual(d["changed_nodes"], [])
        self.assertEqual(d["unchanged_node_count"], 2)
        self.assertTrue(d["graph_available"])


class GraphDiffEdgeTests(unittest.TestCase):
    def test_added_and_removed_edges(self):
        a = _payload([], [_edge("s", "t", "function_to_function")])
        b = _payload([], [_edge("s", "u", "function_to_function")])
        d = diff_graph_payloads(a, b)
        self.assertEqual(
            [(e["source"], e["target"], e["kind"]) for e in d["added_edges"]],
            [("s", "u", "function_to_function")],
        )
        self.assertEqual(
            [(e["source"], e["target"], e["kind"]) for e in d["removed_edges"]],
            [("s", "t", "function_to_function")],
        )

    def test_positional_edge_id_difference_is_not_a_change(self):
        # Same semantic triple, different positional edge:N id -> unchanged (SC-005).
        a = _payload([], [_edge("s", "t", "function_to_function", eid="edge:0")])
        b = _payload([], [_edge("s", "t", "function_to_function", eid="edge:7")])
        d = diff_graph_payloads(a, b)
        self.assertEqual(d["added_edges"], [])
        self.assertEqual(d["removed_edges"], [])


class GraphDiffRobustnessTests(unittest.TestCase):
    def test_missing_payload_sets_graph_unavailable(self):
        d = diff_graph_payloads(None, _payload([_node("function:C.f")], []))
        self.assertFalse(d["graph_available"])
        self.assertEqual(d["added_nodes"], [])
        self.assertEqual(d["removed_nodes"], [])

    def test_both_missing(self):
        d = diff_graph_payloads(None, None)
        self.assertFalse(d["graph_available"])

    def test_output_is_deterministic_and_sorted(self):
        a = _payload([], [])
        b = _payload([_node("function:C.z"), _node("function:C.a")], [])
        d1 = diff_graph_payloads(a, b)
        d2 = diff_graph_payloads(a, b)
        self.assertEqual(d1, d2)
        self.assertEqual([n["id"] for n in d1["added_nodes"]],
                         ["function:C.a", "function:C.z"])


if __name__ == "__main__":
    unittest.main()
