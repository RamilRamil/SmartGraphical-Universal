"""Audit task catalog (feature 016, relocated from web_api).

Enumerates tasks per language and the run-all predicate. Imports the shared
error/service helpers from ``web_support``; never imports ``web_api`` or
``analyze_facade``.
"""
from smartgraphical.services.web_support import (
    ERROR_INVALID_LANGUAGE,
    WebApiError,
    _build_service_safe,
)


# Catalog id for the synthetic "run all rules" task (not in RuleEngine registry).
META_TASK_ALL_ID = "0"


def is_run_all_task(task_id) -> bool:
    if task_id is None:
        return False
    return str(task_id).strip().lower() in frozenset({META_TASK_ALL_ID, "all"})


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
