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


def sanitize_graph_token(token):
    return re.sub(r"[^A-Za-z0-9_]", "_", token)


class GraphBuilder:
    def render(self, model, output_label):
        if graphviz is None:
            print("Error: graphviz Python package is not installed.")
            return
        print("--------------------------------------------------------------------------")
        print("Generating plot ... ")
        dot = graphviz.Digraph(
            "round-table",
            format="png",
            graph_attr={"label": output_label, "splines": "ortho", "nodesep": "1.2"},
        )
        dot.attr(rankdir="LR")

        for index, type_entry in enumerate(model.types):
            with dot.subgraph(name=f"cluster_{index}") as cluster:
                cluster.attr(
                    label=type_entry.name,
                    color=CLUSTER_BORDER_COLOR,
                    penwidth="2",
                    bgcolor=CLUSTER_BACKGROUND_COLOR,
                    fontcolor=CLUSTER_BORDER_COLOR,
                    fontsize="26pt",
                )
                with cluster.subgraph() as section:
                    section.attr("node", shape="ellipse", style="filled")
                    for state_entity in type_entry.state_entities:
                        if state_entity.kind == "object_instance":
                            continue
                        section.node(
                            f"var_{sanitize_graph_token(type_entry.name)}_{sanitize_graph_token(state_entity.name)}",
                            state_entity.name,
                            fillcolor=VAR_FILL_COLOR,
                            color=VAR_FILL_COLOR,
                        )

                    section.attr("node", shape="cylinder")
                    for object_use in type_entry.objects:
                        object_node = f"obj_{sanitize_graph_token(type_entry.name)}_{sanitize_graph_token(object_use.object_name)}"
                        object_label = f"{object_use.object_name}\nContract: {object_use.contract_name}"
                        section.node(object_node, object_label, fillcolor=VAR_FILL_COLOR, color=VAR_FILL_COLOR)

                    section.attr("node", shape="rectangle")
                    for function in type_entry.functions:
                        function_node = f"func_{sanitize_graph_token(type_entry.name)}_{sanitize_graph_token(function.name)}"
                        function_label = f"{function.name}\nInputs: {function.inputs}\nConditionals: {function.conditionals}"
                        section.node(function_node, function_label, fillcolor=FUNC_FILL_COLOR, color=FUNC_FILL_COLOR)
                    for event in type_entry.events:
                        event_node = f"func_{sanitize_graph_token(type_entry.name)}_{sanitize_graph_token(event.name)}"
                        event_label = f"{event.name}\nInputs: {event.inputs}"
                        section.node(event_node, event_label, fillcolor=FUNC_FILL_COLOR, color=FUNC_FILL_COLOR)

        for edge in model.call_edges:
            source_type = sanitize_graph_token(edge.source_type)
            target_type = sanitize_graph_token(edge.target_type)
            if edge.edge_kind in ["state_to_function", "cross_type_state"]:
                dot.edge(
                    f"var_{source_type}_{sanitize_graph_token(edge.source_name)}",
                    f"func_{target_type}_{sanitize_graph_token(edge.target_name)}",
                    color=EDGE_COLOR,
                )
            elif edge.edge_kind in ["function_to_function", "cross_type_call"]:
                dot.edge(
                    f"func_{source_type}_{sanitize_graph_token(edge.source_name)}",
                    f"func_{target_type}_{sanitize_graph_token(edge.target_name)}",
                    color=EDGE_COLOR,
                )
            elif edge.edge_kind == "function_to_system":
                system_node = f"sysfunc_{target_type}_{sanitize_graph_token(edge.target_name)}"
                dot.node(
                    system_node,
                    edge.target_name,
                    shape="parallelogram",
                    style="filled",
                    fillcolor=SYSFUNC_FILL_COLOR,
                    color=SYSFUNC_FILL_COLOR,
                )
                dot.edge(
                    f"func_{source_type}_{sanitize_graph_token(edge.source_name)}",
                    system_node,
                    color=EDGE_COLOR,
                )
            elif edge.edge_kind == "function_to_object":
                dot.edge(
                    f"func_{source_type}_{sanitize_graph_token(edge.source_name)}",
                    f"obj_{target_type}_{sanitize_graph_token(edge.target_name)}",
                    xlabel=edge.label,
                    fontsize="10pt",
                    margin="1",
                    pad="1",
                    color=EDGE_COLOR,
                )

        dot.render(output_label + ".gv", directory="", view=False)
