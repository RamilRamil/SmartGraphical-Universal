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
import os
import time

from smartgraphical.interfaces.cli.main import (
    ALLOWED_MODES,
    _build_service,
    _resolve_language,
)
from smartgraphical.services.serializers import (
    finding_to_dict,
    findings_to_list,
    model_summary_to_dict,
)


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


def _validate_path(path):
    if not path or not isinstance(path, str):
        raise WebApiError(ERROR_INVALID_PATH, "path must be a non-empty string")
    if not os.path.isfile(path):
        raise WebApiError(ERROR_INVALID_PATH, f"source file not found: {path}")


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
        "supported_languages": ["solidity", "c"],
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
    _validate_path(path)
    _validate_mode(mode)
    resolved_language = _resolve_language_safe(path, language)
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
    try:
        context = service.analyze(path)
        findings = service.run_task(context, task_id)
    except WebApiError:
        raise
    except Exception as exc:
        raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = _base_report(path, resolved_language, mode)
    report.update({
        "task": task_id,
        "rules_run": [task_id],
        "findings": findings_to_list(findings),
        "findings_count": len(findings),
        "graph_rendered": False,
        "duration_ms": duration_ms,
    })
    return report


def analyze_all(path, language=None, mode="auditor"):
    """Run all registered rules for the detected language."""
    _validate_path(path)
    _validate_mode(mode)
    resolved_language = _resolve_language_safe(path, language)
    service = _build_service_safe(resolved_language)

    started_at = time.perf_counter()
    try:
        context = service.analyze(path)
        findings = service.run_all(context)
    except Exception as exc:
        raise WebApiError(ERROR_INTERNAL, f"analysis failed: {exc}")

    duration_ms = int((time.perf_counter() - started_at) * 1000)
    report = _base_report(path, resolved_language, mode)
    report.update({
        "task": "all",
        "rules_run": sorted(service.rule_engine.rule_registry.keys(), key=int),
        "findings": findings_to_list(findings),
        "findings_count": len(findings),
        "graph_rendered": False,
        "duration_ms": duration_ms,
    })
    return report


def graph(path, language=None):
    """Return a JSON-safe model summary. Does not render PNG here.

    Web layer can call render_graph separately if it wants a file artifact;
    the summary is enough for JSON clients that draw the graph themselves.
    """
    _validate_path(path)
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
