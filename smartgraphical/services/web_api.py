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

_RE_C_BUNDLE_INC_QUOTED = re.compile(r'#include\s+"([^"]+)"')
_RE_C_BUNDLE_INC_ANGLE = re.compile(r'#include\s+<([^>\n]+)>')
_RE_SOL_IMPORT = re.compile(r"\bimport\s+(.+?);", re.DOTALL)
_RE_RUST_MOD = re.compile(r"\bmod\s+(\w+)\s*;")
_RE_RUST_USE_CRATE = re.compile(r"\buse\s+crate::([\w:]+)")
_RE_RUST_USE_SUPER = re.compile(r"\buse\s+super::([\w:]+)")


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


def _solidity_file_import_paths(source_text: str) -> list:
    lines = []
    for line in source_text.splitlines():
        lines.append(line.split("//")[0])
    buf = "\n".join(lines)
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


def _attach_solidity_bundle_import_edges(bundle_root: str, model_summary: dict) -> None:
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members = manifest.get("members") or []
    tag_by_sol = {}
    for entry in members:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".sol"):
            continue
        base = os.path.basename(rel)
        tag_by_sol[base.lower()] = base

    dedupe = _bundle_import_dedupe(edges, "solidity_import")
    new_edges = []
    for entry in members:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".sol"):
            continue
        consumer_tag = os.path.basename(rel)
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        source_id = _first_type_anchor_id(nodes, consumer_tag)
        if not source_id:
            continue
        seen_provider = set()
        for raw_path in _solidity_file_import_paths(text):
            raw_path = raw_path.strip().replace("\\", "/")
            base = os.path.basename(raw_path)
            if not base.lower().endswith(".sol"):
                continue
            provider_tag = tag_by_sol.get(base.lower())
            if not provider_tag or provider_tag == consumer_tag:
                continue
            if provider_tag in seen_provider:
                continue
            seen_provider.add(provider_tag)
            target_id = _first_type_anchor_id(nodes, provider_tag)
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
    edges.extend(new_edges)
    graph["edges"] = edges
    _revalidate_bundle_graph(model_summary, False)


def _rust_collect_module_links(source_text: str) -> list:
    stripped = _strip_rust_comments(source_text)
    refs = []
    for m in _RE_RUST_MOD.finditer(stripped):
        refs.append(("mod", m.group(1)))
    for m in _RE_RUST_USE_CRATE.finditer(stripped):
        refs.append(("crate", m.group(1).split("::")[0]))
    for m in _RE_RUST_USE_SUPER.finditer(stripped):
        refs.append(("super", m.group(1).split("::")[0]))
    return refs


def _attach_rust_bundle_module_edges(bundle_root: str, model_summary: dict) -> None:
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members = manifest.get("members") or []
    tag_by_rs = {}
    for entry in members:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".rs"):
            continue
        base = os.path.basename(rel)
        stem = os.path.splitext(base)[0].lower()
        tag_by_rs[stem] = base

    dedupe = _bundle_import_dedupe(edges, "rust_module")
    new_edges = []
    for entry in members:
        rel = entry.get("path") or ""
        if not rel.lower().endswith(".rs"):
            continue
        consumer_tag = os.path.basename(rel)
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        source_id = _first_type_anchor_id(nodes, consumer_tag)
        if not source_id:
            continue
        seen = set()
        for _rk, name in _rust_collect_module_links(text):
            stem = name.strip().lower()
            if not stem:
                continue
            provider_tag = tag_by_rs.get(stem)
            if not provider_tag or provider_tag == consumer_tag:
                continue
            if provider_tag in seen:
                continue
            seen.add(provider_tag)
            target_id = _first_type_anchor_id(nodes, provider_tag)
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
    """Basenames of #include targets that look like project .c/.h (not system libs)."""
    cleaned = _clean(source_text)
    out = []
    for rx in (_RE_C_BUNDLE_INC_QUOTED, _RE_C_BUNDLE_INC_ANGLE):
        for m in rx.finditer(cleaned):
            raw = m.group(1).strip().replace("\\", "/")
            base = os.path.basename(raw)
            if base and base.lower().endswith((".h", ".c")):
                out.append(base)
    return out


def _find_c_bundle_tile_id(nodes, source_basename: str, unit_stem: str):
    for n in nodes:
        if str(n.get("group", "")) != "tile":
            continue
        if n.get("source_file") != source_basename:
            continue
        if str(n.get("label", "")) == unit_stem:
            return str(n.get("id", ""))
    return ""


def _attach_c_bundle_include_edges(bundle_root: str, model_summary: dict) -> None:
    """Add tile_to_tile edges for #include of another bundle member (.c/.h)."""
    graph = model_summary.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = list(graph.get("edges") or [])
    manifest_path = os.path.join(bundle_root, BUNDLE_MANIFEST_BASENAME)
    if not os.path.isfile(manifest_path):
        return
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    members = manifest.get("members") or []
    tag_by_base = {}
    for entry in members:
        rel = entry.get("path") or ""
        low = rel.lower()
        if not low.endswith((".c", ".h")):
            continue
        base = os.path.basename(rel)
        tag_by_base[base.lower()] = base

    dedupe = set()
    for e in edges:
        if str(e.get("kind", "")) != "tile_to_tile":
            continue
        if e.get("label") != "bundle_member_include":
            continue
        dedupe.add((str(e.get("source", "")), str(e.get("target", ""))))

    new_edges = []
    for entry in members:
        rel = entry.get("path") or ""
        if not rel.lower().endswith((".c", ".h")):
            continue
        consumer_tag = os.path.basename(rel)
        abs_path = os.path.join(bundle_root, rel)
        if not os.path.isfile(abs_path):
            continue
        with open(abs_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        consumer_stem = os.path.splitext(consumer_tag)[0]
        source_id = _find_c_bundle_tile_id(nodes, consumer_tag, consumer_stem)
        if not source_id:
            continue
        for inc_base in _c_bundle_collect_local_includes(text):
            provider_tag = tag_by_base.get(inc_base.lower())
            if not provider_tag or provider_tag == consumer_tag:
                continue
            prov_stem = os.path.splitext(provider_tag)[0]
            target_id = _find_c_bundle_tile_id(nodes, provider_tag, prov_stem)
            if not target_id:
                continue
            pair = (source_id, target_id)
            if pair in dedupe:
                continue
            dedupe.add(pair)
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
        pairs.append((abs_path, os.path.basename(rel)))
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

    The list always ends with a synthetic "all" task that represents
    `analyze_all`. Each concrete task is backed by a RuleSpec from the
    adapter's rule registry, so the UI can render titles and metadata
    without duplicating the catalog.
    """
    if not language or not isinstance(language, str):
        raise WebApiError(ERROR_INVALID_LANGUAGE, "language must be a non-empty string")
    normalized_language = language.lower()
    service = _build_service_safe(normalized_language)
    registry = service.rule_engine.rule_registry
    ordered_ids = sorted(registry.keys(), key=int)
    tasks = []
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
    tasks.append({
        "id": "all",
        "title": "Run all rules",
        "category": "",
        "portability": "",
        "confidence": "",
        "kind": "meta",
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
        "task": "all",
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
    if resolved_language == "c":
        _attach_c_bundle_include_edges(path, merged)
    elif resolved_language == "solidity":
        _attach_solidity_bundle_import_edges(path, merged)
    elif resolved_language == "rust":
        _attach_rust_bundle_module_edges(path, merged)
    return {
        "status": "ok",
        "artifact": path,
        "language": resolved_language,
        "duration_ms": duration_ms,
        "model_summary": merged,
    }
