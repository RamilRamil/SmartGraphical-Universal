"""JSON-safe serializers for analyzer domain objects.

All serializers are pure functions that return plain Python containers
(dicts, lists, primitives). No web framework is used: the goal is to let
any thin HTTP wrapper call json.dumps on the result directly.
"""

import hashlib


_VIS_ONLY = frozenset({"public", "external", "internal", "private"})
_DECLARED_MODIFIER_MARKER = "__declared_modifier__"

_MODIFIER_COLOR = {
    "payable": "#22c55e",
    "view": "#64748b",
    "pure": "#94a3b8",
    "constant": "#78716c",
    "virtual": "#6366f1",
    "override": "#8b5cf6",
    "onlyowner": "#22c55e",
    "initializer": "#0ea5e9",
}


def _modifier_hex(name):
    key = name.lower()
    if key in _MODIFIER_COLOR:
        return _MODIFIER_COLOR[key]
    digest = hashlib.sha256(name.encode()).hexdigest()
    return f"#{digest[:6]}"


def _graph_modifier_fields(modifiers):
    if not modifiers:
        return None
    raw = [m for m in modifiers if m and m != _DECLARED_MODIFIER_MARKER]
    if not raw:
        return None
    return [{"name": m, "color": _modifier_hex(m)} for m in raw]


def evidence_to_dict(evidence):
    if evidence is None:
        return None
    return {
        "kind": getattr(evidence, "kind", ""),
        "summary": getattr(evidence, "summary", ""),
        "type_name": getattr(evidence, "type_name", ""),
        "function_name": getattr(evidence, "function_name", ""),
        "statement": getattr(evidence, "statement", ""),
        "source_statement": getattr(evidence, "source_statement", ""),
        "confidence_reason": getattr(evidence, "confidence_reason", ""),
    }


def finding_to_dict(finding):
    if finding is None:
        return None
    evidences = getattr(finding, "evidences", []) or []
    return {
        "task_id": getattr(finding, "task_id", ""),
        "legacy_code": getattr(finding, "legacy_code", 0),
        "rule_id": getattr(finding, "rule_id", ""),
        "title": getattr(finding, "title", ""),
        "category": getattr(finding, "category", ""),
        "portability": getattr(finding, "portability", ""),
        "confidence": getattr(finding, "confidence", ""),
        "message": getattr(finding, "message", ""),
        "remediation_hint": getattr(finding, "remediation_hint", ""),
        "evidences": [evidence_to_dict(e) for e in evidences],
    }


def findings_to_list(findings):
    if not findings:
        return []
    return [finding_to_dict(f) for f in findings]


def _function_id(type_name, function_name):
    return f"function:{type_name or '_'}.{function_name}"


def _type_id(type_name):
    return f"type:{type_name}"


def _state_id(type_name, entity_name):
    return f"state:{type_name or '_'}.{entity_name}"


def _external_id(target_name):
    return f"external:{target_name}"


def _event_id(type_name, event_name):
    return f"event:{type_name or '_'}.{event_name}"


def _modifier_id(type_name, modifier_name):
    return f"modifier:{type_name or '_'}.{modifier_name}"


def model_graph_to_dict(model):
    """Return a Cytoscape-friendly {nodes, edges} view of the model.

    Nodes:
    - type nodes are compound parents (group = "type").
    - function nodes are children of their type (group = "function").
    - state-entity nodes (group = "state") are children of their type.
    - event nodes (group = "event") for Solidity events.
    - external/system call targets become free-standing nodes
      (group = "external") so edges always resolve.
    Function nodes may include modifier_details (name + color), and
    modifier_ring_details (declared modifiers applied to function) for
    nested compound ring rendering in the frontend, plus booleans
    calls_contract / calls_system / calls_event / calls_internal derived
    from outgoing edge kinds.
    Edges preserve call_edge kind and label and always reference
    existing node ids.
    """
    if model is None:
        return {"nodes": [], "edges": []}
    types = getattr(model, "types", []) or []
    call_edges = getattr(model, "call_edges", []) or []

    nodes = []
    node_ids = set()

    def add_node(node):
        if node["id"] in node_ids:
            return
        node_ids.add(node["id"])
        nodes.append(node)

    function_lookup = {}
    state_lookup = {}
    event_short_to_ids = {}
    modifier_short_to_ids = {}

    for type_entry in types:
        type_name = getattr(type_entry, "name", "") or "_"
        add_node({
            "id": _type_id(type_name),
            "label": type_name,
            "group": "type",
            "kind": getattr(type_entry, "kind", "") or "",
        })
        declared_modifier_names = set()
        type_functions = getattr(type_entry, "functions", []) or []
        for fn in type_functions:
            fn_modifiers = getattr(fn, "modifiers", []) or []
            if _DECLARED_MODIFIER_MARKER in fn_modifiers:
                fn_name = getattr(fn, "name", "") or ""
                if fn_name:
                    declared_modifier_names.add(fn_name)
        for modifier_name in sorted(declared_modifier_names):
            add_node({
                "id": _modifier_id(type_name, modifier_name),
                "label": modifier_name,
                "group": "modifier",
                "parent": _type_id(type_name),
                "type_name": type_name,
                "modifier_color": _modifier_hex(modifier_name),
            })
            modifier_short_to_ids.setdefault(modifier_name, []).append(
                _modifier_id(type_name, modifier_name),
            )

        for function in type_functions:
            function_name = getattr(function, "name", "") or ""
            if not function_name:
                continue
            function_modifiers = getattr(function, "modifiers", []) or []
            is_declared_modifier = _DECLARED_MODIFIER_MARKER in function_modifiers
            if is_declared_modifier:
                continue
            node_id = _function_id(type_name, function_name)
            mod_details = _graph_modifier_fields(function_modifiers)
            ring_details = None
            if mod_details:
                ring_details = [
                    m for m in mod_details
                    if m["name"] in declared_modifier_names
                ]
            fn_node = {
                "id": node_id,
                "label": function_name,
                "group": "function",
                "parent": _type_id(type_name),
                "type_name": type_name,
                "visibility": getattr(function, "visibility", "") or "",
                "is_entrypoint": bool(getattr(function, "is_entrypoint", False)),
                "source_body": getattr(function, "body", "") or "",
            }
            if mod_details:
                fn_node["modifier_details"] = mod_details
            if ring_details:
                fn_node["modifier_ring_details"] = ring_details
            add_node(fn_node)
            function_lookup.setdefault(function_name, node_id)
        for entity in getattr(type_entry, "state_entities", []) or []:
            entity_name = getattr(entity, "name", "") or ""
            if not entity_name:
                continue
            node_id = _state_id(type_name, entity_name)
            add_node({
                "id": node_id,
                "label": entity_name,
                "group": "state",
                "parent": _type_id(type_name),
                "type_name": type_name,
                "kind": getattr(entity, "kind", "") or "",
            })
            state_lookup.setdefault(entity_name, node_id)
        for ev in getattr(type_entry, "events", []) or []:
            event_name = getattr(ev, "name", "") or ""
            if not event_name:
                continue
            eid = _event_id(type_name, event_name)
            add_node({
                "id": eid,
                "label": event_name,
                "group": "event",
                "parent": _type_id(type_name),
                "type_name": type_name,
            })
            event_short_to_ids.setdefault(event_name, []).append(eid)

    def resolve_endpoint(type_name, target_name):
        if type_name:
            candidate = _function_id(type_name, target_name)
            if candidate in node_ids:
                return candidate
            candidate = _state_id(type_name, target_name)
            if candidate in node_ids:
                return candidate
            candidate = _event_id(type_name, target_name)
            if candidate in node_ids:
                return candidate
            candidate = _modifier_id(type_name, target_name)
            if candidate in node_ids:
                return candidate
        function_match = function_lookup.get(target_name)
        if function_match:
            return function_match
        state_match = state_lookup.get(target_name)
        if state_match:
            return state_match
        ev_ids = event_short_to_ids.get(target_name) or []
        if len(ev_ids) == 1:
            return ev_ids[0]
        if len(ev_ids) > 1 and type_name:
            qualified = _event_id(type_name, target_name)
            if qualified in node_ids:
                return qualified
        if ev_ids:
            return ev_ids[0]
        mod_ids = modifier_short_to_ids.get(target_name) or []
        if len(mod_ids) == 1:
            return mod_ids[0]
        if len(mod_ids) > 1 and type_name:
            qualified = _modifier_id(type_name, target_name)
            if qualified in node_ids:
                return qualified
        if mod_ids:
            return mod_ids[0]
        external_id = _external_id(target_name)
        add_node({
            "id": external_id,
            "label": target_name,
            "group": "external",
        })
        return external_id

    edges = []
    for index, edge in enumerate(call_edges):
        source_type = getattr(edge, "source_type", "") or ""
        source_name = getattr(edge, "source_name", "") or ""
        target_type = getattr(edge, "target_type", "") or ""
        target_name = getattr(edge, "target_name", "") or ""
        if not source_name or not target_name:
            continue
        source_id = resolve_endpoint(source_type, source_name)
        target_id = resolve_endpoint(target_type, target_name)
        edges.append({
            "id": f"edge:{index}",
            "source": source_id,
            "target": target_id,
            "kind": getattr(edge, "edge_kind", "") or "",
            "label": getattr(edge, "label", "") or "",
        })

    outgoing_kinds = {}
    for edge in edges:
        outgoing_kinds.setdefault(edge["source"], set()).add(edge["kind"])

    for node in nodes:
        if node.get("group") != "function":
            continue
        kinds = outgoing_kinds.get(node["id"], set())
        node["calls_internal"] = "function_to_function" in kinds
        node["calls_contract"] = "function_to_object" in kinds
        node["calls_system"] = "function_to_system" in kinds
        node["calls_event"] = "function_to_event" in kinds

    return {"nodes": nodes, "edges": edges}


def model_summary_to_dict(model):
    if model is None:
        return {
            "artifact": None,
            "types_count": 0,
            "functions_count": 0,
            "state_entities_count": 0,
            "guards_count": 0,
            "call_edges_count": 0,
            "graph": {"nodes": [], "edges": []},
        }
    types = getattr(model, "types", []) or []
    functions_count = 0
    state_entities_count = 0
    guards_count = 0
    for type_entry in types:
        functions = getattr(type_entry, "functions", []) or []
        state_entities = getattr(type_entry, "state_entities", []) or []
        functions_count += len(functions)
        state_entities_count += len(state_entities)
        for function in functions:
            guards_count += len(getattr(function, "guards", []) or [])
    artifact = getattr(model, "artifact", None)
    return {
        "artifact": {
            "path": getattr(artifact, "path", ""),
            "language": getattr(artifact, "language", ""),
            "adapter_name": getattr(artifact, "adapter_name", ""),
        } if artifact is not None else None,
        "types_count": len(types),
        "functions_count": functions_count,
        "state_entities_count": state_entities_count,
        "guards_count": guards_count,
        "call_edges_count": len(getattr(model, "call_edges", []) or []),
        "graph": model_graph_to_dict(model),
    }
