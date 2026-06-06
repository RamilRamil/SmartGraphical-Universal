import re

try:
    import graphviz
except ImportError:
    graphviz = None


CLUSTER_BORDER_COLOR = "#4D869C"
CLUSTER_BACKGROUND_COLOR = "#F8F6F422"
VAR_FILL_COLOR = "#95D2B380"
FUNC_FILL_COLOR = "#D2E9E9"
SYSFUNC_FILL_COLOR = "#E3F4F4"
EDGE_COLOR = "#D77FA1"

# Canonical node groups that are compound containers (become graphviz clusters)
# rather than drawn leaf nodes. These mirror the web cytoscape compound parents.
COMPOUND_GROUPS = frozenset({"type", "tile"})

# group -> graphviz node attributes. Consulted via GROUP_STYLE.get(group, DEFAULT).
DEFAULT_NODE_STYLE = {"shape": "rectangle", "style": "filled",
                      "fillcolor": FUNC_FILL_COLOR, "color": FUNC_FILL_COLOR}
GROUP_STYLE = {
    "function": {"shape": "rectangle", "style": "filled",
                 "fillcolor": FUNC_FILL_COLOR, "color": FUNC_FILL_COLOR},
    "event": {"shape": "rectangle", "style": "filled",
              "fillcolor": FUNC_FILL_COLOR, "color": FUNC_FILL_COLOR},
    "state": {"shape": "ellipse", "style": "filled",
              "fillcolor": VAR_FILL_COLOR, "color": VAR_FILL_COLOR},
    "custom_error": {"shape": "note", "style": "filled",
                     "fillcolor": FUNC_FILL_COLOR, "color": FUNC_FILL_COLOR},
    "modifier": {"shape": "hexagon", "style": "filled",
                 "fillcolor": VAR_FILL_COLOR, "color": VAR_FILL_COLOR},
    "workspace": {"shape": "cylinder", "style": "filled",
                  "fillcolor": VAR_FILL_COLOR, "color": VAR_FILL_COLOR},
    "external": {"shape": "parallelogram", "style": "filled",
                 "fillcolor": SYSFUNC_FILL_COLOR, "color": SYSFUNC_FILL_COLOR},
    "external_import": {"shape": "parallelogram", "style": "filled",
                        "fillcolor": SYSFUNC_FILL_COLOR, "color": SYSFUNC_FILL_COLOR},
}

# edge kind -> graphviz edge attributes. Consulted via EDGE_STYLE.get(kind, DEFAULT).
DEFAULT_EDGE_STYLE = {"color": EDGE_COLOR}
EDGE_STYLE = {
    "import_dependency": {"color": EDGE_COLOR, "style": "dashed"},
    "bundle_import": {"color": EDGE_COLOR, "style": "dashed"},
    "function_to_include_template": {"color": EDGE_COLOR, "style": "dotted"},
    "pointer_flow": {"color": EDGE_COLOR, "style": "dashed"},
}


def sanitize_graph_token(token):
    return re.sub(r"[^A-Za-z0-9_]", "_", token)


def _plan_render(graph):
    """Pure planning step: partition the canonical graph dict into graphviz
    clusters (compound parents), their child nodes, top-level nodes, and edges.

    Returns (clusters, top_nodes, edges) where ``clusters`` is an ordered dict
    ``{parent_id: {"label": str, "children": [node, ...]}}``. No graphviz needed,
    so this is what the parity test asserts against ``model_graph_to_dict``.
    """
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    clusters = {}
    compound_ids = set()
    for node in nodes:
        if str(node.get("group", "")) in COMPOUND_GROUPS:
            cid = str(node.get("id", ""))
            if not cid:
                continue
            compound_ids.add(cid)
            clusters.setdefault(cid, {"label": str(node.get("label", "")), "children": []})

    top_nodes = []
    for node in nodes:
        nid = str(node.get("id", ""))
        if not nid or nid in compound_ids:
            continue
        parent = str(node.get("parent", "") or "")
        if parent and parent in clusters:
            clusters[parent]["children"].append(node)
        else:
            top_nodes.append(node)

    return clusters, top_nodes, edges


class GraphBuilder:
    def render(self, model, output_label):
        if graphviz is None:
            print("Error: graphviz Python package is not installed.")
            return
        # Render the SAME canonical projection the web cytoscape view consumes, so
        # the two pillars cannot drift (feature 017, Constitution Principle V).
        from smartgraphical.services.serializers import model_graph_to_dict

        graph = model_graph_to_dict(model)
        clusters, top_nodes, edges = _plan_render(graph)

        print("--------------------------------------------------------------------------")
        print("Generating plot ... ")
        dot = graphviz.Digraph(
            "round-table",
            format="png",
            graph_attr={"label": output_label, "splines": "ortho", "nodesep": "1.2"},
        )
        dot.attr(rankdir="LR")

        for index, (cluster_id, info) in enumerate(clusters.items()):
            with dot.subgraph(name=f"cluster_{index}") as cluster:
                cluster.attr(
                    label=info["label"],
                    color=CLUSTER_BORDER_COLOR,
                    penwidth="2",
                    bgcolor=CLUSTER_BACKGROUND_COLOR,
                    fontcolor=CLUSTER_BORDER_COLOR,
                    fontsize="26pt",
                )
                for node in info["children"]:
                    style = GROUP_STYLE.get(str(node.get("group", "")), DEFAULT_NODE_STYLE)
                    cluster.node(str(node.get("id", "")), str(node.get("label", "")), **style)

        for node in top_nodes:
            style = GROUP_STYLE.get(str(node.get("group", "")), DEFAULT_NODE_STYLE)
            dot.node(str(node.get("id", "")), str(node.get("label", "")), **style)

        for edge in edges:
            attrs = dict(EDGE_STYLE.get(str(edge.get("kind", "")), DEFAULT_EDGE_STYLE))
            label = str(edge.get("label", "") or "")
            if label:
                attrs.setdefault("xlabel", label)
                attrs.setdefault("fontsize", "10pt")
            dot.edge(str(edge.get("source", "")), str(edge.get("target", "")), **attrs)

        dot.render(output_label + ".gv", directory="", view=False)
