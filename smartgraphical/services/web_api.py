"""Pure-Python facade prepared for HTTP endpoints (thin re-export, feature 016).

This module exposes analyze / analyze_all / graph / health / list_tasks
functions that return plain JSON-safe dicts. No web framework is imported: a
thin HTTP wrapper (e.g. FastAPI) can call these functions directly and
json.dumps the result.

Error contract:
- user-input problems raise WebApiError with a stable code.
- any other unexpected failure is surfaced as a WebApiError with code
  "internal_error" by the top-level handlers in each method.

The implementation lives in sibling modules; web_api re-exports the stable
public surface. See specs/016-decompose-web-api/ for the decomposition.
"""
from smartgraphical.services.analyze_facade import (
    analyze,
    analyze_all,
    graph,
    health,
)
from smartgraphical.services.bundle_graph import (
    BUNDLE_MANIFEST_BASENAME,
    _rust_collect_module_links,
    _solidity_file_import_paths,
)
from smartgraphical.services.task_catalog import (
    META_TASK_ALL_ID,
    is_run_all_task,
    list_tasks,
)
from smartgraphical.services.web_support import (
    ERROR_INTERNAL,
    ERROR_INVALID_LANGUAGE,
    ERROR_INVALID_MODE,
    ERROR_INVALID_PATH,
    ERROR_INVALID_TASK,
    WebApiError,
)

__all__ = [
    "health",
    "list_tasks",
    "analyze",
    "analyze_all",
    "graph",
    "is_run_all_task",
    "WebApiError",
    "ERROR_INVALID_PATH",
    "ERROR_INVALID_LANGUAGE",
    "ERROR_INVALID_TASK",
    "ERROR_INVALID_MODE",
    "ERROR_INTERNAL",
]
