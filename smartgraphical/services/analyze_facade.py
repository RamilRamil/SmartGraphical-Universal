"""Analyze / graph / health orchestration facade (feature 016, relocated).

Validates input, resolves language/service, runs analysis, shapes JSON-safe
reports, and delegates bundle graph assembly to ``bundle_graph``. One-way deps:
imports ``web_support``, ``bundle_graph``, ``task_catalog``, serializers, and the
CLI mode list; never imports ``web_api``.
"""
import json
import os
import time

from smartgraphical.interfaces.cli.main import ALLOWED_MODES
from smartgraphical.services.serializers import (
    finding_to_dict,
    merge_bundled_model_summaries,
    model_summary_to_dict,
)
from smartgraphical.services.bundle_graph import (
    BUNDLE_MANIFEST_BASENAME,
    _apply_bundle_edge_hints,
    _attach_c_bundle_include_edges,
    _attach_rust_bundle_module_edges,
    _attach_solidity_bundle_import_edges,
    _attach_solidity_bundle_inheritance_edges,
    _attach_solidity_bundle_inherited_call_edges,
    _consolidate_solidity_bundle_graph,
)
from smartgraphical.services.task_catalog import META_TASK_ALL_ID
from smartgraphical.services.web_support import (
    ERROR_INTERNAL,
    ERROR_INVALID_LANGUAGE,
    ERROR_INVALID_MODE,
    ERROR_INVALID_PATH,
    ERROR_INVALID_TASK,
    WebApiError,
    _build_service_safe,
    _resolve_language_safe,
)


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


def _is_bundle_root(path):
    return os.path.isdir(path) and os.path.isfile(
        os.path.join(path, BUNDLE_MANIFEST_BASENAME),
    )


def _analyze_source(service, abs_path, bundle_root):
    expand_local_imports = not _is_bundle_root(bundle_root)
    return service.analyze(abs_path, expand_local_imports=expand_local_imports)


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


def analyze(path, task_id, language=None, mode="auditor"):
    """Run a single rule (task_id) and return a JSON-safe report."""
    _validate_analysis_target(path)
    _validate_mode(mode)
    pairs = _analysis_source_steps(path)
    resolved_language = _assert_consistent_bundle_language(pairs, language)
    service = _build_service_safe(resolved_language)
    bundle_root = path if _is_bundle_root(path) else None

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
            context = _analyze_source(service, abs_path, bundle_root or abs_path)
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
    bundle_root = path if _is_bundle_root(path) else None

    started_at = time.perf_counter()
    all_findings = []
    try:
        for abs_path, label in pairs:
            context = _analyze_source(service, abs_path, bundle_root or abs_path)
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
            context = _analyze_source(service, path, path)
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
            context = _analyze_source(service, abs_path, path)
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
        _attach_solidity_bundle_inherited_call_edges(path, merged)
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
