# Data Model: Decompose the web_api god-module

This feature introduces no new runtime data entities. The "model" here is the
**module/responsibility decomposition** and the **preserved symbol contract**.

## Modules (entities) and responsibilities

### `bundle_graph.py` (NEW)
- **Responsibility**: Assemble multi-file *bundle* graphs — resolve provider/
  consumer relationships and attach import/inheritance/include/module edges for
  Solidity, C, and Rust; consolidate and revalidate the merged bundle graph.
- **State**: stateless module-level functions + compiled regex constants.
- **Inputs**: model summaries (dicts), bundle manifests, member path sets, raw
  source text.
- **Outputs**: mutated/returned graph dicts (same shapes as today).
- **Public re-export obligation**: `_solidity_file_import_paths`,
  `_rust_collect_module_links`.

### `task_catalog.py` (NEW)
- **Responsibility**: Define the audit-task catalog surface — enumerate tasks per
  language and answer the "run all" predicate.
- **Members**: `META_TASK_ALL_ID`, `is_run_all_task(task_id)`,
  `list_tasks(language)`.
- **Inputs**: language string.
- **Outputs**: JSON-safe task list dict; boolean predicate.

### `analyze_facade.py` (NEW)
- **Responsibility**: Request-level orchestration — validate target/mode, resolve
  language and service, run analysis, build the report, and delegate graph
  assembly to `bundle_graph`. Owns the error contract.
- **Members**: `ERROR_INVALID_PATH`, `ERROR_INVALID_LANGUAGE`,
  `ERROR_INVALID_TASK`, `ERROR_INVALID_MODE`, `ERROR_INTERNAL`, `WebApiError`,
  the `_validate_*` / `_resolve_*_safe` / `_build_service_safe` / `_analyze_source`
  / `_base_report` / `_bundle_member_abs_paths` / `_analysis_source_steps` /
  `_is_bundle_root` / `_assert_consistent_bundle_language` helpers, and the four
  facade functions `health`, `analyze`, `analyze_all`, `graph`.
- **Inputs**: path, task_id, language, mode.
- **Outputs**: JSON-safe report/graph/health dicts; raises `WebApiError`.

### `web_api.py` (BECOMES thin facade)
- **Responsibility**: Stable public entry point. No business logic of its own.
- **Members**: explicit re-exports of all public symbols + the two private
  helpers + the error sentinels, plus `__all__`.

## Dependency graph (one-way, acyclic)

```text
callers (routes, cli, benchmark, adapters, tests)
        │  import from
        ▼
   web_api.py  (facade / re-export)
        │
        ▼
  analyze_facade.py
        │
        ├──────────────► bundle_graph.py ──► adapters._clean,
        │                                     adapters._strip_rust_comments,
        │                                     serializers
        └──────────────► task_catalog.py ──► adapter rule registries,
                                              interfaces.cli.main

(analyze_facade also imports: serializers, analysis_service,
 interfaces.cli.main; bundle_graph/task_catalog never import web_api.)
```

## Preserved symbol contract (validation rules)

Every symbol in this set MUST remain importable from
`smartgraphical.services.web_api` with identical behaviour:

| Symbol | Kind | Current external importers (examples) |
|--------|------|----------------------------------------|
| `graph` | function | routes, cli, tests (24 uses) |
| `analyze_all` | function | routes, benchmark, tests (12 uses) |
| `analyze` | function | routes, cli, tests (11 uses) |
| `list_tasks` | function | routes, tests (9 uses) |
| `health` | function | routes, tests (2 uses) |
| `is_run_all_task` | function | cli/tests (1 use) |
| `WebApiError` | class | routes/errors.py |
| `ERROR_INVALID_LANGUAGE` | constant | routes/errors.py |
| `_solidity_file_import_paths` | private fn | other modules/tests (6 uses) |
| `_rust_collect_module_links` | private fn | tests (1 use) |

Additional `ERROR_*` sentinels (`ERROR_INVALID_PATH`, `ERROR_INVALID_TASK`,
`ERROR_INVALID_MODE`, `ERROR_INTERNAL`) are re-exported for safety even where no
current external importer exists, because they are part of the documented error
contract.

## State transitions

None. No persisted or mutable cross-call state is introduced or moved in a way
that changes lifecycle.
