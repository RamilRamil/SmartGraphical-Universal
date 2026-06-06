# Contract: web_api public facade (preserved)

This refactor changes **no** contract. This document pins the surface that MUST
remain identical after the move, so the facade re-export test and the
constitution's Principle VI gate have an authoritative reference.

## Importable from `smartgraphical.services.web_api`

```python
from smartgraphical.services.web_api import (
    # public functions — signatures unchanged
    health,                       # () -> dict
    list_tasks,                   # (language) -> dict
    analyze,                      # (path, task_id, language=None, mode="auditor") -> dict
    analyze_all,                  # (path, language=None, mode="auditor") -> dict
    graph,                        # (path, language=None) -> dict
    is_run_all_task,              # (task_id) -> bool
    # error contract
    WebApiError,                  # Exception subclass
    ERROR_INVALID_PATH,           # str sentinel
    ERROR_INVALID_LANGUAGE,       # str sentinel
    ERROR_INVALID_TASK,           # str sentinel
    ERROR_INVALID_MODE,           # str sentinel
    ERROR_INTERNAL,               # str sentinel
    # externally-used private helpers (kept importable verbatim)
    _solidity_file_import_paths,  # (source_text) -> list
    _rust_collect_module_links,   # (source_text) -> list
)
```

## Behavioural invariants (unchanged)

1. **Purity / JSON-safety**: `health`, `list_tasks`, `analyze`, `analyze_all`,
   `graph` return plain JSON-safe dicts with the exact same keys, nesting, and
   value types as before the refactor (Principle VI).
2. **Error identity**: `WebApiError` is the same class object; `except
   web_api.WebApiError` continues to catch errors raised by the relocated code.
   The `ERROR_*` string values are unchanged, so callers comparing `exc.code`
   keep matching.
3. **Graph payloads**: `graph(...)` and the graph section of `analyze_all(...)`
   are byte-for-byte identical for every existing fixture (Solidity, C, Rust;
   single-file and bundle).
4. **Task catalog**: `list_tasks(language)` returns the identical task list
   (order and contents) for solidity / c / rust, as pinned by the three
   `*_task_coverage.json` manifest tests.
5. **No new public symbols**: the set above is exactly the prior public surface;
   nothing added, nothing removed.

## Verification

- Existing: `tests/unit/test_web_api_contract.py`, the three
  `test_*_task_coverage_declared.py`, golden/serializer tests, and the HTTP
  contract/integration tests.
- New: `tests/unit/test_web_api_facade_reexports.py` asserts every symbol in this
  contract is importable from `web_api` and that `WebApiError` identity holds
  (the same object reached via `web_api.WebApiError` and via the owning module).
