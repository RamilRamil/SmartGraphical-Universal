"""Pure structural graph diff (feature 018).

Compares two scans' graph payloads (the `web_api.graph` output stored per scan)
and reports nodes added/removed/changed and edges added/removed. Node identity is
the canonical, stable node `id` (unified across renderers in feature 017); edge
identity is the semantic triple ``(source, target, kind)`` — never the positional
``edge:N`` id, which is unstable across scans.

Pure and dependency-free so it is trivially unit-testable; the HistoryService
wraps it with scan loading and the same same-artifact/not-found guards as the
findings diff.
"""


def _graph_section(payload):
    """Return (nodes, edges) from a graph payload, tolerating None/missing keys."""
    if not isinstance(payload, dict):
        return [], []
    model_summary = payload.get("model_summary")
    if not isinstance(model_summary, dict):
        return [], []
    graph = model_summary.get("graph")
    if not isinstance(graph, dict):
        return [], []
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    return (nodes if isinstance(nodes, list) else [],
            edges if isinstance(edges, list) else [])


def _node_signature(node):
    return (
        str(node.get("group", "") or ""),
        str(node.get("label", "") or ""),
        str(node.get("kind", "") or ""),
    )


def _node_descriptor(node):
    group, label, kind = _node_signature(node)
    return {"id": str(node.get("id", "") or ""), "group": group, "label": label, "kind": kind}


def _edge_key(edge):
    return (
        str(edge.get("source", "") or ""),
        str(edge.get("target", "") or ""),
        str(edge.get("kind", "") or ""),
    )


def _edge_descriptor(edge):
    source, target, kind = _edge_key(edge)
    return {"source": source, "target": target, "kind": kind,
            "label": str(edge.get("label", "") or "")}


def diff_graph_payloads(payload_a, payload_b):
    """Structurally diff two graph payloads. Deterministic (sorted output).

    Returns a JSON-safe dict (see specs/018 data-model.md) WITHOUT scan/artifact
    ids — the history layer attaches those. `graph_available` is False when either
    side has no graph to compare.
    """
    available = bool(payload_a) and bool(payload_b)
    if not available:
        # Nothing meaningful to compare if either side lacks a graph; return an
        # empty diff flagged unavailable rather than reporting one-sided churn.
        return {
            "graph_available": False,
            "added_nodes": [], "removed_nodes": [], "changed_nodes": [],
            "added_edges": [], "removed_edges": [],
            "added_node_count": 0, "removed_node_count": 0, "changed_node_count": 0,
            "added_edge_count": 0, "removed_edge_count": 0, "unchanged_node_count": 0,
        }
    nodes_a, edges_a = _graph_section(payload_a)
    nodes_b, edges_b = _graph_section(payload_b)

    # Node identity = canonical id.
    nodes_a_by_id = {str(n.get("id", "") or ""): n for n in nodes_a if n.get("id")}
    nodes_b_by_id = {str(n.get("id", "") or ""): n for n in nodes_b if n.get("id")}

    added_nodes, removed_nodes, changed_nodes = [], [], []
    unchanged_node_count = 0
    for nid in nodes_b_by_id:
        if nid not in nodes_a_by_id:
            added_nodes.append(_node_descriptor(nodes_b_by_id[nid]))
    for nid in nodes_a_by_id:
        if nid not in nodes_b_by_id:
            removed_nodes.append(_node_descriptor(nodes_a_by_id[nid]))
    for nid in nodes_a_by_id:
        if nid not in nodes_b_by_id:
            continue
        sig_a = _node_signature(nodes_a_by_id[nid])
        sig_b = _node_signature(nodes_b_by_id[nid])
        if sig_a == sig_b:
            unchanged_node_count += 1
            continue
        before = {"group": sig_a[0], "label": sig_a[1], "kind": sig_a[2]}
        after = {"group": sig_b[0], "label": sig_b[1], "kind": sig_b[2]}
        changed_nodes.append({"id": nid, "before": before, "after": after})

    # Edge identity = (source, target, kind); positional edge id ignored.
    edges_a_by_key = {_edge_key(e): e for e in edges_a}
    edges_b_by_key = {_edge_key(e): e for e in edges_b}
    added_edges = [_edge_descriptor(edges_b_by_key[k]) for k in edges_b_by_key if k not in edges_a_by_key]
    removed_edges = [_edge_descriptor(edges_a_by_key[k]) for k in edges_a_by_key if k not in edges_b_by_key]

    added_nodes.sort(key=lambda d: d["id"])
    removed_nodes.sort(key=lambda d: d["id"])
    changed_nodes.sort(key=lambda d: d["id"])
    added_edges.sort(key=lambda d: (d["source"], d["target"], d["kind"]))
    removed_edges.sort(key=lambda d: (d["source"], d["target"], d["kind"]))

    return {
        "graph_available": available,
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "changed_nodes": changed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "added_node_count": len(added_nodes),
        "removed_node_count": len(removed_nodes),
        "changed_node_count": len(changed_nodes),
        "added_edge_count": len(added_edges),
        "removed_edge_count": len(removed_edges),
        "unchanged_node_count": unchanged_node_count,
    }
