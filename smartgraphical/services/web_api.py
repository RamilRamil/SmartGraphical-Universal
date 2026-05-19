"""Pure-Python facade prepared for future HTTP endpoints.

This module exposes analyze / analyze_all / graph / health functions that
return plain JSON-safe dicts. No web framework is imported: a thin HTTP
wrapper (e.g. Flask, FastAPI) can call these functions directly and call
json.dumps on the result.

Error contract:
- user-input problems raise WebApiError with a stable code.
- any other unexpected failure is surfaced as a WebApiError with code
  "internal_error" by the top-level handlers in each method.
"""
import hashlib
import json
import os
import re
import time
from pathlib import PurePosixPath

from smartgraphical.adapters.c_base.adapter import _clean
from smartgraphical.adapters.rust_stellar.adapter import _strip_rust_comments
from smartgraphical.interfaces.cli.main import (
    ALLOWED_MODES,
    _build_service,
    _resolve_language,
)
from smartgraphical.services.serializers import (
    _validate_and_normalize_payload,
    finding_to_dict,
    merge_bundled_model_summaries,
    model_summary_to_dict,
)


BUNDLE_MANIFEST_BASENAME = "sg_bundle_manifest.json"

# Catalog id for the synthetic "run all rules" task (not in RuleEngine registry).
META_TASK_ALL_ID = "0"


def is_run_all_task(task_id) -> bool:
    if task_id is None:
        return False
    return str(task_id).strip().lower() in frozenset({META_TASK_ALL_ID, "all"})

_RE_C_BUNDLE_INC_QUOTED = re.compile(r'#include\s+"([^"]+)"')
_RE_C_BUNDLE_INC_ANGLE = re.compile(r'#include\s+<([^>\n]+)>')
_RE_SOL_IMPORT = re.compile(r"\bimport\s+(.+?);", re.DOTALL)
_RE_RUST_MOD_HEAD = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*([;{])",
)
_RE_RUST_USE_CRATE = re.compile(r"\buse\s+crate::([\w:]+)")
_RE_RUST_USE_SUPER = re.compile(r"\buse\s+super::([\w:]+)")


def _touch_bundle_stat(stats: dict | None, key: str, delta: int = 1) -> None:
    if stats is None:
        return
    stats[key] = stats.get(key, 0) + delta


def _solidity_same_basename_count(members_rels, raw_path: str) -> int:
    raw_path = (raw_path or "").strip().replace("\\", "/")
    if not raw_path.lower().endswith(".sol"):
        return 0
    base = os.path.basename(raw_path).lower()
    return sum(
        1
        for r in members_rels
        if r.lower().endswith(".sol") and os.path.basename(r).lower() == base
    )


def _c_same_basename_count(members_rels, raw_inc: str) -> int:
    raw = (raw_inc or "").strip().replace("\\", "/")
    low = raw.lower()
    if not low.endswith((".h", ".c")):
        return 0
    base = os.path.basename(raw).lower()
    return sum(
        1
        for r in members_rels
        if os.path.basename(r).lower() == base
    )


def _normalize_manifest_c_include_prefixes(raw) -> list:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        if not isinstance(item, str):
            continue
        s = item.strip().replace("\\", "/").strip("/")
        if not s:
            continue
        if any(p == ".." for p in PurePosixPath(s).parts):
            continue
        if s.startswith("/") or (len(s) > 1 and s[1] == ":"):
            continue
        out.append(s)
    return out


def _apply_bundle_edge_hints(graph: dict, stats: dict | None) -> None:
    if not stats:
        return
    interesting = {k: int(v) for k, v in stats.items() if int(v) > 0}
    if not interesting:
        return
    hints = graph.setdefault("exploration_hints", {})
    if not isinstance(hints, dict):
        hints = {}
        graph["exploration_hints"] = hints
    hints["bundle_edge_resolution"] = interesting


def _bundle_members_rel_set(manifest):
    members = manifest.get("members") or []
    out = set()
    for entry in members:
        rel = entry.get("path") or ""
        if rel:
            out.add(rel)
    return out


def _resolve_solidity_provider_rel(members_rels, consumer_rel, raw_path):
    raw_path = (raw_path or "").strip().replace("\\", "/")
    if not raw_path.lower().endswith(".sol"):
        return None
    direct = str(PurePosixPath(raw_path))
    if direct in members_rels:
        return direct
    joined = str(PurePosixPath(PurePosixPath(consumer_rel).parent / raw_path))
    if joined in members_rels:
        return joined
    base = os.path.basename(raw_path).lower()
    matches = [
        r
        for r in members_rels
        if r.lower().endswith(".sol") and os.path.basename(r).lower() == base
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _normalize_manifest_solidity_remappings(raw) -> list:
    """Return (prefix, target) pairs longest-prefix-first for manifest ``solidity_remappings``."""
    if not isinstance(raw, list) or not raw:
        return []
    out = []
    for item in raw:
        prefix = None
        target = None
        if isinstance(item, dict):
            prefix = item.get("prefix")
            target = item.get("path")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            prefix, target = item[0], item[1]
        if not isinstance(prefix, str) or not isinstance(target, str):
            continue
        prefix = prefix.strip().replace("\\", "/")
        target = target.strip().replace("\\", "/")
        if not prefix:
            continue
        out.append((prefix, target))
    out.sort(key=lambda x: -len(x[0]))
    return out


def _apply_solidity_remappings(raw_path: str, remaps: list) -> str:
    if not remaps:
        return raw_path
    s = (raw_path or "").strip().replace("\\", "/")
    for prefix, path in remaps:
        if s.startswith(prefix):
            return path + s[len(prefix):]
    return s


def _resolve_c_provider_rel(members_rels, consumer_rel, raw_inc, include_prefixes=None):
    raw = (raw_inc or "").strip().replace("\\", "/")
    if not raw:
        return None
    low = raw.lower()
    if not low.endswith((".h", ".c")):
        return None
    direct = str(PurePosixPath(raw))
    if direct in members_rels:
        return direct
    joined = str(PurePosixPath(PurePosixPath(consumer_rel).parent / raw))
    if joined in members_rels:
        return joined
    if any(p == ".." for p in PurePosixPath(raw).parts):
        return None
    prefixes = include_prefixes or []
    for prefix in prefixes:
        cand = str(PurePosixPath(prefix) / raw)
        if any(p == ".." for p in PurePosixPath(cand).parts):
            continue
        if cand in members_rels:
            return cand
    base = os.path.basename(raw).lower()
    matches = [r for r in members_rels if os.path.basename(r).lower() == base]
    if len(matches) == 1:
        return matches[0]
    return None


def _resolve_rust_mod_provider_rel(members_rels, consumer_rel, stem, prefix_segments=()):
    """Resolve ``mod stem;`` using consumer file dir plus optional inline-mod path.

    ``prefix_segments`` is the chain of parent inline modules (e.g. ``account`` for
    ``mod account { mod logic; }`` -> ``.../account/logic.rs``).
    """
    stem = stem.split("::")[0].strip().lower()
    if not stem:
        return None
    parent = PurePosixPath(consumer_rel).parent
    dir_path = parent
    for seg in prefix_segments:
        dir_path = dir_path / seg
    for cand in (str(dir_path / f"{stem}.rs"), str(dir_path / stem / "mod.rs")):
        if cand in members_rels:
            return cand
    return None


def _resolve_rust_super_provider_rel(members_rels, consumer_rel, stem):
    """Resolve ``super::stem`` (file-path heuristic).

    Prefer the grandparent directory (one path segment up); if that is the
    bundle root, fall back to the parent directory so ``src/child.rs`` can
    resolve ``super::sibling`` to ``src/sibling.rs``.
    """
    stem = stem.split("::")[0].strip().lower()
    if not stem:
        return None
    parent = PurePosixPath(consumer_rel).parent
    super_parent = parent.parent
    search_dirs = []
    if str(super_parent) != ".":
        search_dirs.append(super_parent)
    search_dirs.append(parent)
    seen = set()
    for d in search_dirs:
        for extra in (f"{stem}.rs", f"{stem}/mod.rs"):
            cand = str(d / extra)
            if cand in seen:
                continue
            seen.add(cand)
            if cand in members_rels:
                return cand
    return None


def _rust_crate_root_dirs(members_rels):
    roots = []
    seen = set()
    for r in members_rels:
        if not r.lower().endswith(".rs"):
            continue
        p = PurePosixPath(r)
        if p.name not in ("lib.rs", "main.rs"):
            continue
        root = str(p.parent)
        if root not in seen:
            seen.add(root)
            roots.append(root)
    return roots


def _rust_pick_crate_root_for_consumer(members_rels, consumer_rel):
    """If manifest exposes lib.rs/main.rs roots, scope ``crate::`` to one root when unambiguous."""
    roots = _rust_crate_root_dirs(members_rels)
    if not roots:
        return None
    cons = consumer_rel.replace("\\", "/")
    applicable = []
    for root in roots:
        if root == ".":
            if "/" not in cons:
                applicable.append(root)
        elif cons == root or cons.startswith(root + "/"):
            applicable.append(root)
    if len(applicable) == 1:
        return applicable[0]
    if not applicable:
        return None
    applicable.sort(key=len, reverse=True)
    inner = applicable[0]
    if all((x.startswith(inner + "/") or x == inner) for x in applicable):
        return inner
    return None


def _rust_member_pool_for_crate_root(members_rels, root: str):
    if root == ".":
        return set(members_rels)
    return {r for r in members_rels if r == root or r.startswith(root + "/")}


def _resolve_rust_crate_provider_rel(members_rels, consumer_rel, stem):
    stem = stem.split("::")[0].strip().lower()
    if not stem:
        return None
    picked_root = _rust_pick_crate_root_for_consumer(members_rels, consumer_rel)
    pool = (
        _rust_member_pool_for_crate_root(members_rels, picked_root)
        if picked_root is not None
        else set(members_rels)
    )
    matches = [
        r
        for r in pool
        if r.lower().endswith(".rs") and PurePosixPath(r).stem.lower() == stem
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _strip_solidity_block_comments(source_text: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", source_text, flags=re.DOTALL)


def _solidity_strip_line_comment(line: str) -> str:
    """Drop a trailing // comment; do not treat // inside quotes as comment start."""
    in_quote = None
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if in_quote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_quote:
                in_quote = None
            i += 1
            continue
        if c in "\"'":
            in_quote = c
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            return line[:i].rstrip()
        i += 1
    return line


def _solidity_clause_to_paths(clause: str) -> list:
    clause = " ".join(clause.split())
    paths = []
    m = re.search(r'\bfrom\s+["\']([^"\']+)["\']', clause)
    if m:
        paths.append(m.group(1).strip())
        return paths
    for mm in re.finditer(r'["\']([^"\']+\.sol)["\']', clause):
        paths.append(mm.group(1).strip())
    return paths


_RE_SOL_CONTRACT_IS = re.compile(
    r'\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+([^{;]+)',
    re.MULTILINE,
)


def _solidity_contract_inheritance_pairs(source_text: str) -> list:
    buf = _strip_solidity_block_comments(source_text)
    out = []
    for match in _RE_SOL_CONTRACT_IS.finditer(buf):
        child = match.group(1).strip()
        parents = [p.strip() for p in match.group(2).split(',') if p.strip()]
        if child and parents:
            out.append((child, parents))
    return out


def _function_node_ids_by_type(
    nodes: list,
    type_label: str,
    func_label: str,
    source_file: str | None = None,
) -> list:
    ids = []
    for node in nodes:
        if str(node.get("group", "")) != "function":
            continue
        if str(node.get("type_name", "")) != type_label:
            continue
        if str(node.get("label", "")) != func_label:
            continue
        if source_file is not None and str(node.get("source_file", "")) != source_file:
            continue
        node_id = str(node.get("id", ""))
        if node_id:
            ids.append(node_id)
    return ids


def _line_numbers_for_pattern(file_lines: list, pattern: str) -> list:
    nums = []
    for num, line in enumerate(file_lines, start=1):
        if re.search(pattern, line):
            nums.append(num)
    return nums


def _type_node_ids_by_label(nodes: list, label: str, source_file: str | None = None) -> list:
    ids = []
    for node in nodes:
        if str(node.get("group", "")) != "type":
            continue
        if str(node.get("label", "")) != label:
            continue
        if source_file is not None and str(node.get("source_file", "")) != source_file:
            continue
        node_id = str(node.get("id", ""))
        if node_id:
            ids.append(node_id)
    return ids


def _consolidate_solidity_bundle_graph(model_summary: dict) -> None:
    """Merge duplicate external stubs; wire imports to in-bundle type nodes."""
    graph = model_summary.get("graph") or {}
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])

    type_by_label = {}
    for node in nodes:
        if str(node.get("group", "")) != "type":
            continue
        label = str(node.get("label", ""))
        if label and label not in type_by_label:
            type_by_label[label] = str(node.get("id", ""))

    id_remap = {}
    symbol_canonical = {}
    path_canonical = {}

    def _register_canonical(old_id: str, new_id: str) -> None:
        if not old_id or not new_id or old_id == new_id:
            return
        root_old = id_remap.get(old_id, old_id)
        root_new = id_remap.get(new_id, new_id)
        if root_old == root_new:
            return
        id_remap[root_old] = root_new
        id_remap[old_id] = root_new

    kept = []
    for node in nodes:
        nid = str(node.get("id", ""))
        if not nid:
            continue
        group = str(node.get("group", ""))
        label = str(node.get("label", ""))

        if group in ("external", "external_import") and label in type_by_label:
            _register_canonical(nid, type_by_label[label])
            continue

        if group == "external_import":
            path = str(node.get("import_path") or "").strip()
            if path:
                if path in path_canonical:
                    _register_canonical(nid, path_canonical[path])
                    continue
                path_canonical[path] = nid
            if label:
                if label in symbol_canonical:
                    _register_canonical(nid, symbol_canonical[label])
                    continue
                symbol_canonical[label] = nid

        kept.append(node)

    def _resolve_id(node_id: str) -> str:
        seen = set()
        cur = node_id
        while cur in id_remap and cur not in seen:
            seen.add(cur)
            cur = id_remap[cur]
        return cur

    unique_nodes = {}
    for node in kept:
        node["id"] = _resolve_id(str(node.get("id", "")))
        nid = str(node.get("id", ""))
        if nid and nid not in unique_nodes:
            unique_nodes[nid] = node
    kept = list(unique_nodes.values())

    new_edges = []
    edge_seen = set()
    for edge in edges:
        src = _resolve_id(str(edge.get("source", "")))
        tgt = _resolve_id(str(edge.get("target", "")))
        if not src or not tgt or src == tgt:
            continue
        kind = str(edge.get("kind", ""))
        key = (src, tgt, kind, str(edge.get("label", "")))
        if key in edge_seen:
            continue
        edge_seen.add(key)
        edge["source"] = src
        edge["target"] = tgt
        new_edges.append(edge)

    kept_ids = {str(n.get("id", "")) for n in kept if n.get("id")}
    kept = [n for n in kept if str(n.get("id", "")) in kept_ids]

    graph["nodes"] = kept
    graph["edges"] = new_edges
    _revalidate_bundle_graph(model_summary, False)


def _inheritance_target_ids(nodes: list, node_ids: set, parent_name: str) -> list:
    targets = _type_node_ids_by_label(nodes, parent_name)
    if targets:
        return targets
    legacy = f"external:import:{parent_name}"
    if legacy in node_ids:
        return [legacy]
    return []


def _solidity_file_import_paths(source_text: str) -> list:
    lines = []
    for line in source_text.splitlines():
        lines.append(_solidity_strip_line_comment(line))
    buf = "\n".join(lines)
    buf = _strip_solidity_block_comments(buf)
    out = []
    for m in _RE_SOL_IMPORT.finditer(buf):
        out.extend(_solidity_clause_to_paths(m.group(1).strip()))
    return out


def _first_type_anchor_id(nodes: list, source_tag: str) -> str:
    cands = []
    for n in nodes:
        if str(n.get("group", "")) != "type":
            continue
        if n.get("source_file") != source_tag:
            continue
        cands.append((str(n.get("label", "")), str(n.get("id", ""))))
    if not cands:
        return ""
    cands.sort(key=lambda x: x[0])
    return cands[0][1]


def _external_import_path_node_id(import_path: str) -> str:
    digest = hashlib.sha256((import_path or "").encode("utf-8")).hexdigest()[:16]
    return f"external:importpath:{digest}"


def _ensure_external_import_path_node(nodes: list, node_ids: set, import_path: str) -> str:
    path = (import_path or "").strip()
    if not path:
        return ""
    node_id = _external_import_path_node_id(path)
    if node_id in node_ids:
        return node_id
    base = path.rsplit("/", 1)[-1] if "/" in path else path
    label = base.rsplit(".", 1)[0] if base.lower().endswith(".sol") else base
    if not label:
        label = path
    nodes.append({
        "id": node_id,
        "label": label,
        "group": "external_import",
        "import_path": path,
        "resolution": "missing_in_bundle",
    })
    node_ids.add(node_id)
    return node_id


def _bundle_import_dedupe(edges: list, label: str) -> set:
    d = set()
    for e in edges:
        if e.get("label") != label:
            continue
        if str(e.get("kind", "")) != "bundle_import":
            continue
        d.add((str(e.get("source", "")), str(e.get("target", ""))))
    return d


def _revalidate_bundle_graph(model_summary: dict, is_c_profile: bool) -> None:
    graph = model_summary.get("graph") or {}
    validated_nodes, validated_edges = _validate_and_normalize_payload(
        list(graph.get("nodes", [])),
        list(graph.get("edges", [])),
        is_c_profile,
    )
    graph["nodes"] = validated_nodes
    graph["edges"] = validated_edges
    if is_c_profile:
        hints = graph.get("exploration_hints")
        if isinstance(hints, dict):
            hints["node_count"] = len(validated_nodes)
            hints["edge_count"] = len(validated_edges)
            hints["call_edge_count"] = len(validated_edges)
    model_summary["graph"] = graph
    model_summary["call_edges_count"] = len(validated_edges)


def _attach_solidity_bundle_import_edges(
    bundle_root: str,
    model_summary: dict,
    bundle_stats: dict | None = None,
) -> None:
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members_rels = _bundle_members_rel_set(manifest)
    sol_remaps = _normalize_manifest_solidity_remappings(manifest.get("solidity_remappings"))

    dedupe = _bundle_import_dedupe(edges, "solidity_import")
    import_dep_dedupe: set = set()
    node_ids = {str(n.get("id", "")) for n in nodes if n.get("id")}
    new_edges = []
    for entry in manifest.get("members") or []:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".sol"):
            continue
        consumer_rel = rel
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        source_id = _first_type_anchor_id(nodes, consumer_rel)
        if not source_id:
            continue
        seen_provider = set()
        for raw_path in _solidity_file_import_paths(text):
            provider_rel = None
            candidates = []
            remapped = _apply_solidity_remappings(raw_path, sol_remaps)
            if remapped != raw_path:
                candidates.append(remapped)
            candidates.append(raw_path)
            for cand in candidates:
                provider_rel = _resolve_solidity_provider_rel(
                    members_rels, consumer_rel, cand,
                )
                if provider_rel:
                    break
            if not provider_rel or provider_rel == consumer_rel:
                if bundle_stats is not None and raw_path.lower().endswith(".sol"):
                    if _solidity_same_basename_count(members_rels, raw_path) > 1:
                        _touch_bundle_stat(
                            bundle_stats,
                            "skipped_solidity_ambiguous_basename",
                        )
                    elif not provider_rel:
                        _touch_bundle_stat(
                            bundle_stats,
                            "skipped_solidity_unresolved_import",
                        )
                if provider_rel:
                    continue
                target_id = _ensure_external_import_path_node(
                    nodes, node_ids, raw_path,
                )
                if not target_id:
                    continue
                pair = (source_id, target_id)
                if pair in import_dep_dedupe:
                    continue
                import_dep_dedupe.add(pair)
                digest = hashlib.sha256(
                    f"{source_id}\0{target_id}\0{raw_path}\0unresolved".encode("utf-8"),
                ).hexdigest()[:12]
                new_edges.append({
                    "id": f"bundle_sol_unresolved:{digest}",
                    "source": source_id,
                    "target": target_id,
                    "kind": "import_dependency",
                    "label": raw_path,
                    "import_path": raw_path,
                    "resolution": "missing_in_bundle",
                })
                continue
            if provider_rel in seen_provider:
                continue
            seen_provider.add(provider_rel)
            target_id = _first_type_anchor_id(nodes, provider_rel)
            if not target_id:
                continue
            pair = (source_id, target_id)
            if pair in dedupe:
                continue
            dedupe.add(pair)
            digest = hashlib.sha256(
                f"{source_id}\0{target_id}\0{raw_path}".encode("utf-8"),
            ).hexdigest()[:12]
            new_edges.append({
                "id": f"bundle_sol:{digest}",
                "source": source_id,
                "target": target_id,
                "kind": "bundle_import",
                "label": "solidity_import",
                "import_path": raw_path,
            })

    if not new_edges:
        return
    graph["nodes"] = nodes
    edges.extend(new_edges)
    graph["edges"] = edges
    _revalidate_bundle_graph(model_summary, False)


def _attach_solidity_bundle_inheritance_edges(
    bundle_root: str,
    model_summary: dict,
) -> None:
    """Link contract inheritance across bundle members (``cross_type_call``)."""
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    node_ids = {str(n.get("id", "")) for n in nodes if n.get("id")}
    dedupe = set()
    new_edges = []
    for entry in manifest.get("members") or []:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".sol"):
            continue
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        for child_name, parents in _solidity_contract_inheritance_pairs(text):
            source_ids = _type_node_ids_by_label(nodes, child_name, rel)
            if not source_ids:
                continue
            source_id = source_ids[0]
            for parent in parents:
                for target_id in _inheritance_target_ids(nodes, node_ids, parent):
                    if target_id == source_id:
                        continue
                    pair = (source_id, target_id)
                    if pair in dedupe:
                        continue
                    dedupe.add(pair)
                    digest = hashlib.sha256(
                        f"{source_id}\0{target_id}\0extends\0{parent}".encode("utf-8"),
                    ).hexdigest()[:12]
                    new_edges.append({
                        "id": f"bundle_sol_extends:{digest}",
                        "source": source_id,
                        "target": target_id,
                        "kind": "cross_type_call",
                        "label": f"extends {parent}",
                    })
                child_ctor_ids = _function_node_ids_by_type(
                    nodes, child_name, "constructor", rel,
                )
                parent_ctor_ids = _function_node_ids_by_type(
                    nodes, parent, "constructor",
                )
                if not child_ctor_ids or not parent_ctor_ids:
                    continue
                if not re.search(rf"\b{re.escape(parent)}\s*\(", text):
                    continue
                ctor_source = child_ctor_ids[0]
                ctor_target = parent_ctor_ids[0]
                ctor_pair = (ctor_source, ctor_target)
                if ctor_pair in dedupe:
                    continue
                dedupe.add(ctor_pair)
                line_nums = _line_numbers_for_pattern(
                    text.splitlines(),
                    rf"\b{re.escape(parent)}\s*\(",
                )
                digest = hashlib.sha256(
                    f"{ctor_source}\0{ctor_target}\0ctor\0{parent}".encode("utf-8"),
                ).hexdigest()[:12]
                callsite = ""
                if line_nums and 0 < line_nums[0] <= len(text.splitlines()):
                    callsite = text.splitlines()[line_nums[0] - 1].strip()
                new_edges.append({
                    "id": f"bundle_sol_ctor:{digest}",
                    "source": ctor_source,
                    "target": ctor_target,
                    "kind": "cross_type_call",
                    "label": f"{parent}()",
                    "callsite": callsite,
                    "line_numbers": line_nums[:6],
                })
    if not new_edges:
        return
    edges.extend(new_edges)
    graph["edges"] = edges
    _revalidate_bundle_graph(model_summary, False)


def _rust_naive_match_brace(source: str, open_idx: int) -> int:
    """Return index of brace matching ``source[open_idx]``, or -1 (string-unaware)."""
    if open_idx >= len(source) or source[open_idx] != "{":
        return -1
    depth = 0
    i = open_idx
    while i < len(source):
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _rust_collect_file_module_declarations(
    stripped: str,
    lo: int,
    hi: int,
    stack: list,
    out: list,
) -> None:
    """Fill ``out`` with ``(tuple(stack), name)`` for each file-module ``mod name;``."""
    i = lo
    while i < hi:
        m = _RE_RUST_MOD_HEAD.search(stripped, i, hi)
        if not m:
            break
        name = m.group(1)
        kind = m.group(2)
        if kind == ";":
            out.append((tuple(stack), name))
            i = m.end()
            continue
        brace_open = m.end() - 1
        if brace_open >= hi or stripped[brace_open] != "{":
            i = m.end()
            continue
        close = _rust_naive_match_brace(stripped, brace_open)
        if close < 0 or close > hi:
            i = m.end()
            continue
        _rust_collect_file_module_declarations(
            stripped, brace_open + 1, close, stack + [name], out,
        )
        i = close + 1


def _rust_collect_module_links(source_text: str) -> list:
    stripped = _strip_rust_comments(source_text)
    mod_refs = []
    _rust_collect_file_module_declarations(
        stripped, 0, len(stripped), [], mod_refs,
    )
    refs = [("mod", name, prefix) for prefix, name in mod_refs]
    for m in _RE_RUST_USE_CRATE.finditer(stripped):
        refs.append(("crate", m.group(1).split("::")[0], ()))
    for m in _RE_RUST_USE_SUPER.finditer(stripped):
        refs.append(("super", m.group(1).split("::")[0], ()))
    return refs


def _attach_rust_bundle_module_edges(
    bundle_root: str,
    model_summary: dict,
    bundle_stats: dict | None = None,
) -> None:
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members_rels = _bundle_members_rel_set(manifest)

    dedupe = _bundle_import_dedupe(edges, "rust_module")
    new_edges = []
    for entry in manifest.get("members") or []:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".rs"):
            continue
        consumer_rel = rel
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        source_id = _first_type_anchor_id(nodes, consumer_rel)
        if not source_id:
            continue
        seen = set()
        for kind, name, mod_prefix in _rust_collect_module_links(text):
            stem = name.split("::")[0]
            if kind == "crate":
                provider_rel = _resolve_rust_crate_provider_rel(members_rels, consumer_rel, stem)
            elif kind == "super":
                provider_rel = _resolve_rust_super_provider_rel(
                    members_rels, consumer_rel, stem,
                )
            else:
                provider_rel = _resolve_rust_mod_provider_rel(
                    members_rels, consumer_rel, stem, mod_prefix,
                )
            if not provider_rel or provider_rel == consumer_rel:
                if bundle_stats is not None:
                    _touch_bundle_stat(bundle_stats, "skipped_rust_unresolved_module")
                continue
            if provider_rel in seen:
                continue
            seen.add(provider_rel)
            target_id = _first_type_anchor_id(nodes, provider_rel)
            if not target_id:
                continue
            pair = (source_id, target_id)
            if pair in dedupe:
                continue
            dedupe.add(pair)
            digest = hashlib.sha256(
                f"{source_id}\0{target_id}\0{stem}".encode("utf-8"),
            ).hexdigest()[:12]
            new_edges.append({
                "id": f"bundle_rs:{digest}",
                "source": source_id,
                "target": target_id,
                "kind": "bundle_import",
                "label": "rust_module",
                "module_ref": stem,
            })

    if not new_edges:
        return
    edges.extend(new_edges)
    graph["edges"] = edges
    _revalidate_bundle_graph(model_summary, False)


def _c_bundle_collect_local_includes(source_text: str) -> list:
    """Paths from #include \"...\" / <...> that look like project .c/.h (not system libs)."""
    cleaned = _clean(source_text)
    out = []
    for rx in (_RE_C_BUNDLE_INC_QUOTED, _RE_C_BUNDLE_INC_ANGLE):
        for m in rx.finditer(cleaned):
            raw = m.group(1).strip().replace("\\", "/")
            base = os.path.basename(raw)
            if base and base.lower().endswith((".h", ".c")):
                out.append(raw)
    return out


def _find_c_bundle_tile_id(nodes, source_rel: str, unit_stem: str):
    for n in nodes:
        if str(n.get("group", "")) != "tile":
            continue
        if n.get("source_file") != source_rel:
            continue
        if str(n.get("label", "")) == unit_stem:
            return str(n.get("id", ""))
    return ""


def _attach_c_bundle_include_edges(
    bundle_root: str,
    model_summary: dict,
    bundle_stats: dict | None = None,
) -> None:
    """Add tile_to_tile edges for #include of another bundle member (.c/.h)."""
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members_rels = _bundle_members_rel_set(manifest)
    c_prefixes = _normalize_manifest_c_include_prefixes(manifest.get("c_include_prefixes"))

    dedupe = set()
    for e in edges:
        if str(e.get("kind", "")) != "tile_to_tile":
            continue
        if e.get("label") != "bundle_member_include":
            continue
        dedupe.add((str(e.get("source", "")), str(e.get("target", ""))))

    new_edges = []
    for entry in manifest.get("members") or []:
        rel = entry.get("path") or ""
        if not rel.lower().endswith((".c", ".h")):
            continue
        consumer_rel = rel
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        consumer_stem = os.path.splitext(os.path.basename(consumer_rel))[0]
        source_id = _find_c_bundle_tile_id(nodes, consumer_rel, consumer_stem)
        if not source_id:
            continue
        for raw_inc in _c_bundle_collect_local_includes(text):
            provider_rel = _resolve_c_provider_rel(
                members_rels, consumer_rel, raw_inc, c_prefixes,
            )
            if not provider_rel or provider_rel == consumer_rel:
                if bundle_stats is not None:
                    if _c_same_basename_count(members_rels, raw_inc) > 1:
                        _touch_bundle_stat(bundle_stats, "skipped_c_ambiguous_basename")
                    else:
                        _touch_bundle_stat(bundle_stats, "skipped_c_unresolved_include")
                continue
            prov_stem = os.path.splitext(os.path.basename(provider_rel))[0]
            target_id = _find_c_bundle_tile_id(nodes, provider_rel, prov_stem)
            if not target_id:
                continue
            pair = (source_id, target_id)
            if pair in dedupe:
                continue
            dedupe.add(pair)
            inc_base = os.path.basename(raw_inc)
            digest = hashlib.sha256(
                f"{source_id}\0{target_id}\0{inc_base}".encode("utf-8"),
            ).hexdigest()[:12]
            fact = {
                "is_heuristic": False,
                "confidence": "high",
            }
            new_edges.append({
                "id": f"bundle_inc:{digest}",
                "source": source_id,
                "target": target_id,
                "kind": "tile_to_tile",
                "label": "bundle_member_include",
                "included_basename": inc_base,
                **fact,
            })

    if not new_edges:
        return
    edges.extend(new_edges)
    graph["edges"] = edges
    _revalidate_bundle_graph(model_summary, True)


ERROR_INVALID_PATH = "invalid_path"
ERROR_INVALID_LANGUAGE = "invalid_language"
ERROR_INVALID_TASK = "invalid_task"
ERROR_INVALID_MODE = "invalid_mode"
ERROR_INTERNAL = "internal_error"


class WebApiError(Exception):
    """User-facing API error with a stable code and message."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self):
        return {"status": "error", "code": self.code, "message": self.message}


def _validate_analysis_target(path):
    if not path or not isinstance(path, str):
        raise WebApiError(ERROR_INVALID_PATH, "path must be a non-empty string")
    if os.path.isfile(path):
        return
    candidate = os.path.join(path, BUNDLE_MANIFEST_BASENAME)
    if os.path.isdir(path) and os.path.isfile(candidate):
        return
    raise WebApiError(ERROR_INVALID_PATH, f"source file or bundle not found: {path}")


def _bundle_member_abs_paths(bundle_root):
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members = manifest.get("members") or []
    pairs = []
    for entry in sorted(members, key=lambda item: item.get("path") or ""):
        rel = entry.get("path") or ""
        if not rel:
            continue
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            raise WebApiError(
                ERROR_INVALID_PATH,
                f"bundle member missing on disk: {rel}",
            )
        pairs.append((abs_path, rel))
    if not pairs:
        raise WebApiError(ERROR_INVALID_PATH, "bundle manifest lists no files")
    return pairs


def _analysis_source_steps(path):
    if os.path.isfile(path):
        return [(path, os.path.basename(path))]
    return _bundle_member_abs_paths(path)


def _assert_consistent_bundle_language(pairs, language_hint):
    first = _resolve_language_safe(pairs[0][0], language_hint)
    for abs_path, _ in pairs[1:]:
        other = _resolve_language_safe(abs_path, language_hint)
        if other != first:
            raise WebApiError(
                ERROR_INVALID_LANGUAGE,
                "bundle mixes languages or file extensions",
            )
    return first


def _validate_mode(mode):
    if mode not in ALLOWED_MODES:
        raise WebApiError(
            ERROR_INVALID_MODE,
            f"mode must be one of {', '.join(ALLOWED_MODES)}",
        )


def _resolve_language_safe(path, language):
    try:
        return _resolve_language(path, language)
    except Exception as exc:
        raise WebApiError(ERROR_INVALID_LANGUAGE, str(exc))


def _build_service_safe(language):
    try:
        return _build_service(language)
    except Exception as exc:
        raise WebApiError(ERROR_INVALID_LANGUAGE, str(exc))


def _base_report(artifact_path, language, mode):
    return {
        "status": "ok",
        "artifact": artifact_path,
        "language": language,
        "mode": mode,
        "duration_ms": 0,
    }


def health():
    """Lightweight readiness check for the analyzer stack."""
    return {
        "status": "ok",
        "service": "smartgraphical",
        "supported_languages": ["solidity", "c", "rust"],
        "supported_modes": list(ALLOWED_MODES),
    }


def list_tasks(language):
    """Return the ordered list of task descriptors for the given language.

    The list starts with a synthetic meta task (id ``0``) for `analyze_all`,
    then every RuleSpec from the adapter registry in numeric order.
    """
    if not language or not isinstance(language, str):
        raise WebApiError(ERROR_INVALID_LANGUAGE, "language must be a non-empty string")
    normalized_language = language.lower()
    service = _build_service_safe(normalized_language)
    registry = service.rule_engine.rule_registry
    ordered_ids = sorted(registry.keys(), key=int)
    tasks = [{
        "id": META_TASK_ALL_ID,
        "title": "Run all rules",
        "category": "",
        "portability": "",
        "confidence": "",
        "kind": "meta",
    }]
    for task_id in ordered_ids:
        spec = registry[task_id]
        tasks.append({
            "id": task_id,
            "title": getattr(spec, "title", "") or "",
            "category": getattr(spec, "category", "") or "",
            "portability": getattr(spec, "portability", "") or "",
            "confidence": getattr(spec, "confidence", "") or "",
            "kind": "rule",
        })
    return {
        "language": normalized_language,
        "tasks": tasks,
        "count": len(tasks),
    }


def analyze(path, task_id, language=None, mode="auditor"):
    """Run a single rule (task_id) and return a JSON-safe report."""
    _validate_analysis_target(path)
    _validate_mode(mode)
    pairs = _analysis_source_steps(path)
    resolved_language = _assert_consistent_bundle_language(pairs, language)
    service = _build_service_safe(resolved_language)

    task_id = str(task_id).strip() if task_id is not None else ""
    if not task_id:
        raise WebApiError(ERROR_INVALID_TASK, "task_id must be non-empty")
    if task_id not in service.rule_engine.rule_registry:
        allowed = sorted(service.rule_engine.rule_registry.keys(), key=int)
        raise WebApiError(
            ERROR_INVALID_TASK,
            f"task_id must be one of [{', '.join(allowed)}]",
        )

    started_at = time.perf_counter()
    all_findings = []
    try:
        for abs_path, label in pairs:
            context = service.analyze(abs_path)
            findings = service.run_task(context, task_id)
            for item in findings:
                row = finding_to_dict(item)
                row["source_file"] = label
                all_findings.append(row)
    except WebApiError:
        raise
    except Exception as exc:
        raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = _base_report(path, resolved_language, mode)
    report.update({
        "task": task_id,
        "rules_run": [task_id],
        "findings": all_findings,
        "findings_count": len(all_findings),
        "graph_rendered": False,
        "duration_ms": duration_ms,
    })
    return report


def analyze_all(path, language=None, mode="auditor"):
    """Run all registered rules for the detected language."""
    _validate_analysis_target(path)
    _validate_mode(mode)
    pairs = _analysis_source_steps(path)
    resolved_language = _assert_consistent_bundle_language(pairs, language)
    service = _build_service_safe(resolved_language)

    started_at = time.perf_counter()
    all_findings = []
    try:
        for abs_path, label in pairs:
            context = service.analyze(abs_path)
            findings = service.run_all(context)
            for item in findings:
                row = finding_to_dict(item)
                row["source_file"] = label
                all_findings.append(row)
    except Exception as exc:
        raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = _base_report(path, resolved_language, mode)
    report.update({
        "task": META_TASK_ALL_ID,
        "rules_run": sorted(service.rule_engine.rule_registry.keys(), key=int),
        "findings": all_findings,
        "findings_count": len(all_findings),
        "graph_rendered": False,
        "duration_ms": duration_ms,
    })
    return report


def graph(path, language=None):
    """Return a JSON-safe model summary. Does not render PNG here.

    Web layer can call render_graph separately if it wants a file artifact;
    the summary is enough for JSON clients that draw the graph themselves.
    """
    _validate_analysis_target(path)
    if os.path.isfile(path):
        resolved_language = _resolve_language_safe(path, language)
        service = _build_service_safe(resolved_language)
        started_at = time.perf_counter()
        try:
            context = service.analyze(path)
        except Exception as exc:
            raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

        model = getattr(context, "normalized_model", None)
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        summary = model_summary_to_dict(model)
        return {
            "status": "ok",
            "artifact": path,
            "language": resolved_language,
            "duration_ms": duration_ms,
            "model_summary": summary,
        }

    pairs = _bundle_member_abs_paths(path)
    resolved_language = _assert_consistent_bundle_language(pairs, language)
    service = _build_service_safe(resolved_language)
    started_at = time.perf_counter()
    summaries = []
    try:
        for abs_path, label in pairs:
            context = service.analyze(abs_path)
            summaries.append((label, model_summary_to_dict(context.normalized_model)))
    except Exception as exc:
        raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    merged = merge_bundled_model_summaries(path, summaries)
    bundle_stats: dict = {}
    if resolved_language == "c":
        _attach_c_bundle_include_edges(path, merged, bundle_stats)
    elif resolved_language == "solidity":
        _attach_solidity_bundle_import_edges(path, merged, bundle_stats)
        _attach_solidity_bundle_inheritance_edges(path, merged)
        _consolidate_solidity_bundle_graph(merged)
    elif resolved_language == "rust":
        _attach_rust_bundle_module_edges(path, merged, bundle_stats)
    _apply_bundle_edge_hints(merged.get("graph") or {}, bundle_stats)
    return {
        "status": "ok",
        "artifact": path,
        "language": resolved_language,
        "duration_ms": duration_ms,
        "model_summary": merged,
    }
