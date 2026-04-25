"""JSON-safe serializers for analyzer domain objects.

All serializers are pure functions that return plain Python containers
(dicts, lists, primitives). No web framework is used: the goal is to let
any thin HTTP wrapper call json.dumps on the result directly.
"""

import hashlib


_VIS_ONLY = frozenset({"public", "external", "internal", "private"})
_DECLARED_MODIFIER_MARKER = "__declared_modifier__"
_GRAPH_SCHEMA_VERSION = "1.0"

_C_NODE_ALLOWED_NODE_GROUPS = frozenset({
    "tile",
    "function",
    "workspace",
    "global_state",
    "syscall",
    "external",
})

_C_NODE_ALLOWED_EDGE_KINDS = frozenset({
    "function_to_function",
    "function_to_workspace",
    "tile_to_tile",
    "function_to_syscall",
    "pointer_flow",
})

_C_NODE_NODE_GROUP_ALIASES = {
    "type": "tile",
    "state": "workspace",
}

_C_NODE_EDGE_KIND_ALIASES = {
    "function_to_system": "function_to_syscall",
}

_C_NODE_HEURISTIC_EDGE_KINDS = frozenset({
    "pointer_flow",
})

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
        "line_number": getattr(evidence, "line_number", 0),
        "line_numbers": getattr(evidence, "line_numbers", []) or [],
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


def _is_c_profile_graph(model):
    artifact = getattr(model, "artifact", None)
    if artifact is None:
        return False
    language = (getattr(artifact, "language", "") or "").lower()
    return language == "c"


def _canonicalize_node_group(group, is_c_profile):
    if not is_c_profile:
        return group
    canonical = _C_NODE_NODE_GROUP_ALIASES.get(group, group)
    if canonical in _C_NODE_ALLOWED_NODE_GROUPS:
        return canonical
    return group


def _canonicalize_edge_kind(kind, is_c_profile):
    if not is_c_profile:
        return kind
    canonical = _C_NODE_EDGE_KIND_ALIASES.get(kind, kind)
    if canonical in _C_NODE_ALLOWED_EDGE_KINDS:
        return canonical
    return kind


def _normalized_artifact_path(model):
    artifact = getattr(model, "artifact", None)
    if artifact is None:
        return "_"
    raw_path = getattr(artifact, "path", "") or ""
    path = raw_path.replace("\\", "/").strip()
    if not path:
        return "_"
    while path.startswith("./"):
        path = path[2:]
    return path or "_"


def _stable_c_node_ids(nodes, edges, model):
    path_part = _normalized_artifact_path(model)
    id_map = {}
    used_ids = set()
    suffix_source = {}

    def reserve(node, base_id):
        candidate = base_id
        if candidate not in used_ids:
            used_ids.add(candidate)
            return candidate
        old_id = str(node.get("id", ""))
        digest = hashlib.sha256(old_id.encode()).hexdigest()[:8]
        candidate = f"{base_id}.{digest}"
        if candidate not in used_ids:
            used_ids.add(candidate)
            return candidate
        index = suffix_source.get(base_id, 2)
        while f"{base_id}.{index}" in used_ids:
            index += 1
        suffix_source[base_id] = index + 1
        candidate = f"{base_id}.{index}"
        used_ids.add(candidate)
        return candidate

    for node in nodes:
        old_id = str(node.get("id", ""))
        group = _canonicalize_node_group(node.get("group", ""), True)
        label = str(node.get("label", ""))
        if group == "tile":
            base_id = f"tile:{label}"
        elif group == "function":
            base_id = f"function:{path_part}.{label}"
        elif group == "workspace":
            base_id = f"workspace:{label}"
        elif group == "syscall":
            base_id = f"syscall:{label}"
        elif group == "external":
            if old_id.startswith("external:") and old_id.count(":") >= 2:
                base_id = old_id
            else:
                base_id = f"external:unresolved_symbol:{label}"
        elif group == "global_state":
            base_id = f"global_state:{label}"
        else:
            base_id = old_id
        id_map[old_id] = reserve(node, base_id)

    for node in nodes:
        old_id = str(node.get("id", ""))
        node["id"] = id_map.get(old_id, old_id)
        parent_id = node.get("parent", "")
        if parent_id:
            node["parent"] = id_map.get(str(parent_id), str(parent_id))

    for edge in edges:
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        edge["source"] = id_map.get(source_id, source_id)
        edge["target"] = id_map.get(target_id, target_id)


def _external_class_for_unresolved(edge_kind, symbol):
    kind = (edge_kind or "").strip()
    name = (symbol or "").strip().lower()
    if kind in {"function_to_syscall", "function_to_system"}:
        return "unresolved_syscall"
    if "syscall" in name:
        return "unresolved_syscall"
    if any(marker in name for marker in ("->", "(*", "fnptr", "callback")):
        return "unresolved_fnptr"
    if "::" in name or "." in name:
        return "unresolved_lib"
    return "unresolved_symbol"


def _external_id_with_class(symbol, edge_kind=""):
    resolved_symbol = (symbol or "").strip() or "_"
    external_class = _external_class_for_unresolved(edge_kind, resolved_symbol)
    return f"external:{external_class}:{resolved_symbol}"


def _c_node_edge_fact_fields(kind):
    normalized_kind = (kind or "").strip()
    is_heuristic = normalized_kind in _C_NODE_HEURISTIC_EDGE_KINDS
    confidence = "heuristic" if is_heuristic else "high"
    return {
        "is_heuristic": is_heuristic,
        "confidence": confidence,
    }


def _drop_parent_cycles(nodes):
    by_id = {str(node.get("id", "")): node for node in nodes}
    for node in nodes:
        start_id = str(node.get("id", ""))
        parent_id = str(node.get("parent", "") or "")
        if not parent_id:
            continue
        seen = {start_id}
        cursor = parent_id
        has_cycle = False
        while cursor:
            if cursor in seen:
                has_cycle = True
                break
            seen.add(cursor)
            parent_node = by_id.get(cursor)
            if parent_node is None:
                cursor = ""
                continue
            cursor = str(parent_node.get("parent", "") or "")
        if has_cycle:
            node.pop("parent", None)


def _validate_and_normalize_payload(nodes, edges, is_c_profile):
    unique_nodes = []
    node_ids = set()
    for node in nodes:
        node_id = str(node.get("id", ""))
        if not node_id or node_id in node_ids:
            continue
        node_ids.add(node_id)
        unique_nodes.append(node)
    _drop_parent_cycles(unique_nodes)

    valid_edges = []
    edge_ids = set()
    for edge in edges:
        edge_id = str(edge.get("id", ""))
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if not edge_id or edge_id in edge_ids:
            continue
        if source not in node_ids or target not in node_ids:
            continue
        edge_ids.add(edge_id)
        valid_edges.append(edge)

    if is_c_profile:
        for node in unique_nodes:
            group = str(node.get("group", ""))
            if group not in _C_NODE_ALLOWED_NODE_GROUPS:
                node["experimental_group"] = group
                node["group"] = "external"
        for edge in valid_edges:
            kind = str(edge.get("kind", ""))
            if kind not in _C_NODE_ALLOWED_EDGE_KINDS:
                edge["experimental_kind"] = kind
                edge["kind"] = "pointer_flow"

    return unique_nodes, valid_edges


def _derive_write_paths(nodes, edges):
    function_nodes = {
        str(node.get("id", "")): node
        for node in nodes
        if node.get("group") == "function"
    }
    internal_by_source = {}
    for edge in edges:
        if edge.get("kind") != "function_to_function":
            continue
        source_id = str(edge.get("source", ""))
        internal_by_source.setdefault(source_id, []).append(edge)

    for node_id, node in function_nodes.items():
        paths = []
        seen_paths = set()
        own_writes = node.get("state_writes", []) or []
        for statement in own_writes[:3]:
            text = f"self -> {statement}"
            if text in seen_paths:
                continue
            seen_paths.add(text)
            paths.append({"path": text, "confidence": "high"})

        for edge in internal_by_source.get(node_id, []):
            target_id = str(edge.get("target", ""))
            callee = function_nodes.get(target_id)
            if not callee:
                continue
            callee_writes = callee.get("state_writes", []) or []
            if not callee_writes:
                continue
            first_write = str(callee_writes[0]).strip()
            if not first_write:
                continue
            args_map = edge.get("args_map", []) or []
            if args_map:
                for arg in args_map[:3]:
                    param = str(arg.get("param", "arg")).strip() or "arg"
                    value = str(arg.get("value", "")).strip() or "?"
                    source_kind = str(arg.get("source_kind", "unknown")).strip() or "unknown"
                    text = (
                        f"{param} <- {value} ({source_kind}) -> "
                        f"{callee.get('label', target_id)} -> {first_write}"
                    )
                    if text in seen_paths:
                        continue
                    seen_paths.add(text)
                    paths.append({"path": text, "confidence": "heuristic"})
            else:
                text = f"internal call -> {callee.get('label', target_id)} -> {first_write}"
                if text in seen_paths:
                    continue
                seen_paths.add(text)
                paths.append({"path": text, "confidence": "heuristic"})
        node["write_paths"] = paths


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
        return {
            "graph_schema_version": _GRAPH_SCHEMA_VERSION,
            "nodes": [],
            "edges": [],
        }
    is_c_profile = _is_c_profile_graph(model)
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
        used_modifier_names = set()
        type_functions = getattr(type_entry, "functions", []) or []
        for fn in type_functions:
            fn_modifiers = getattr(fn, "modifiers", []) or []
            if _DECLARED_MODIFIER_MARKER in fn_modifiers:
                fn_name = getattr(fn, "name", "") or ""
                if fn_name:
                    declared_modifier_names.add(fn_name)
                continue
            for mod_name in fn_modifiers:
                if mod_name and mod_name != _DECLARED_MODIFIER_MARKER:
                    used_modifier_names.add(mod_name)
        all_visible_modifier_names = sorted(declared_modifier_names | used_modifier_names)
        for modifier_name in all_visible_modifier_names:
            is_declared_modifier = modifier_name in declared_modifier_names
            add_node({
                "id": _modifier_id(type_name, modifier_name),
                "label": modifier_name,
                "group": "modifier",
                "parent": _type_id(type_name),
                "type_name": type_name,
                "modifier_color": _modifier_hex(modifier_name),
                "modifier_origin": "declared" if is_declared_modifier else "inherited_or_external",
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
                    if m["name"] in all_visible_modifier_names
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
                "full_source": getattr(function, "full_source", "") or "",
                "state_reads": [],
                "state_writes": [],
                "guards": [
                    str(guard).strip()
                    for guard in (getattr(function, "guards", []) or [])
                    if str(guard).strip()
                ],
                "write_paths": [],
            }
            read_entities = []
            for access in (getattr(function, "read_accesses", []) or []):
                entity_name = (getattr(access, "entity_name", "") or "").strip()
                if entity_name:
                    read_entities.append(entity_name)
            fn_node["state_reads"] = sorted(set(read_entities))
            write_entities = []
            for access in (getattr(function, "mutations", []) or []):
                statement = str(access).strip()
                if statement:
                    write_entities.append(statement)
            fn_node["state_writes"] = list(dict.fromkeys(write_entities))
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
                "source_body": getattr(entity, "raw_signature", "") or "",
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

    def resolve_endpoint(type_name, target_name, edge_kind=""):
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
        if is_c_profile:
            external_id = _external_id_with_class(target_name, edge_kind=edge_kind)
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
        edge_kind = getattr(edge, "edge_kind", "") or ""
        source_id = resolve_endpoint(source_type, source_name, edge_kind=edge_kind)
        target_id = resolve_endpoint(target_type, target_name, edge_kind=edge_kind)
        edges.append({
            "id": f"edge:{index}",
            "source": source_id,
            "target": target_id,
            "kind": edge_kind,
            "label": getattr(edge, "label", "") or "",
            "callsite": getattr(edge, "callsite", "") or "",
            "args_map": getattr(edge, "args_map", []) or [],
            "line_numbers": getattr(edge, "line_numbers", []) or [],
        })

    if is_c_profile:
        _stable_c_node_ids(nodes, edges, model)

    _derive_write_paths(nodes, edges)

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

    normalized_nodes = []
    for node in nodes:
        canonical_group = _canonicalize_node_group(node.get("group", ""), is_c_profile)
        normalized_node = {
            "id": str(node.get("id", "")),
            "group": str(canonical_group),
            "label": str(node.get("label", "")),
        }
        for key, value in node.items():
            if key in normalized_node:
                continue
            normalized_node[key] = value
        normalized_nodes.append(normalized_node)

    normalized_edges = []
    for edge in edges:
        canonical_kind = _canonicalize_edge_kind(edge.get("kind", ""), is_c_profile)
        normalized_edge = {
            "id": str(edge.get("id", "")),
            "source": str(edge.get("source", "")),
            "target": str(edge.get("target", "")),
            "kind": str(canonical_kind),
        }
        for key, value in edge.items():
            if key in normalized_edge:
                continue
            normalized_edge[key] = value
        if is_c_profile:
            fact_fields = _c_node_edge_fact_fields(canonical_kind)
            normalized_edge["is_heuristic"] = fact_fields["is_heuristic"]
            normalized_edge["confidence"] = fact_fields["confidence"]
        normalized_edges.append(normalized_edge)

    normalized_nodes, normalized_edges = _validate_and_normalize_payload(
        normalized_nodes,
        normalized_edges,
        is_c_profile,
    )

    return {
        "graph_schema_version": _GRAPH_SCHEMA_VERSION,
        "nodes": normalized_nodes,
        "edges": normalized_edges,
    }


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
