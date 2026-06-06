# Feature Specification: Decompose the web_api god-module

**Feature Branch**: `016-decompose-web-api`

**Created**: 2026-06-06

**Status**: Draft

**Input**: User description: "Decompose the web_api.py god-module (~1485 lines) into focused, single-responsibility services without changing any observable behavior. Extract graph/bundle assembly, task catalog, and the analyze facade behind the same public signatures so all callers (HTTP routes, CLI, tests) keep working. Pure structural refactor: no rule output, no JSON shape, no graph payload may change. Out of scope: unifying CLI/web renderers and graph diff."

## Overview

`smartgraphical/services/web_api.py` has grown to ~1485 lines and mixes four
unrelated responsibilities: (1) the analyze/graph facade that HTTP routes and the
CLI call, (2) the task catalog (`list_tasks`, `is_run_all_task`), (3) a large
bundle-graph assembly engine (~1000 lines of `_attach_*` / `_resolve_*` /
`_consolidate_*` / `_revalidate_*` helpers for Solidity / C / Rust multi-file
bundles), and (4) shared validation/language-resolution helpers. This breadth
makes the module hard to navigate, test in isolation, and extend — and it blocks
the two later block-D features (renderer unification and graph diff), which both
need a clean graph-assembly seam.

This feature is a **pure structural refactor**: split the module into cohesive
units while keeping every observable behaviour, public signature, and import path
identical. The existing test suite (486 passing) plus golden/serializer tests are
the safety net.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Bundle-graph assembly lives in its own module (Priority: P1)

A maintainer extending multi-file bundle graph logic (Solidity import/inheritance
edges, C include edges, Rust module edges) can open a single focused module that
contains only graph-assembly code, instead of scrolling past the analyze facade
and task catalog inside a 1485-line file.

**Why this priority**: The bundle-assembly helpers are ~two-thirds of the file
and the single biggest source of its size and coupling. Extracting them delivers
the largest readability win and creates the clean graph seam the later block-D
features depend on. It is the natural MVP slice.

**Independent Test**: After extraction, the full test suite (unit + integration +
golden + serializer) passes unchanged, and the graph payloads returned by
`graph(...)` / `analyze_all(...)` are byte-for-byte identical to a pre-refactor
snapshot for the Solidity, C, and Rust bundle fixtures.

**Acceptance Scenarios**:

1. **Given** the current bundle fixtures, **When** `graph(path)` is called before
   and after the refactor, **Then** the returned graph dictionaries are equal.
2. **Given** a caller that imports a bundle helper that other modules/tests
   already use (`_solidity_file_import_paths`, `_rust_collect_module_links`),
   **When** they import it from `smartgraphical.services.web_api`, **Then** the
   import still resolves and returns the same result.
3. **Given** the extracted module, **When** a maintainer reads it, **Then** it
   contains only bundle/graph-assembly responsibilities (no task catalog, no
   HTTP-facing facade orchestration).

---

### User Story 2 - Task catalog and analyze facade are separated (Priority: P2)

A maintainer changing the task catalog (the list of audit tasks exposed to the
UI/API) or the analyze/health orchestration can do so in dedicated modules whose
scope matches the change, without touching graph-assembly code.

**Why this priority**: Second-largest clarity win. The task catalog and the
analyze facade are conceptually distinct from graph assembly and from each other;
separating them completes the single-responsibility goal. Lower priority than US1
because these clusters are smaller and already relatively self-contained.

**Independent Test**: `list_tasks(language)`, `is_run_all_task(...)`,
`analyze(...)`, `analyze_all(...)`, `graph(...)`, and `health()` keep identical
signatures and outputs (verified by the existing contract tests and the
task-coverage manifests), with their implementations now residing in
focused modules.

**Acceptance Scenarios**:

1. **Given** the three task-coverage manifest tests (Solidity/C/Rust), **When**
   they run after the refactor, **Then** they pass unchanged.
2. **Given** `analyze`, `analyze_all`, `graph`, `health`, `list_tasks`,
   `is_run_all_task`, **When** called with the same inputs as before, **Then**
   outputs (including error types/codes) are identical.

---

### User Story 3 - web_api.py is a thin, documented facade (Priority: P3)

Any existing caller (HTTP routes, CLI, benchmark, adapters, tests) that imports
from `smartgraphical.services.web_api` continues to work without modification,
because web_api.py remains the stable public entry point and simply re-exports
the relocated symbols.

**Why this priority**: This is the compatibility guarantee that makes the refactor
safe to land without touching ~17 caller files. It is P3 only because it is the
natural by-product of US1+US2 done correctly, not a separate body of work.

**Independent Test**: Grep confirms no caller file outside
`services/web_api.py` changed its import statements, and every symbol previously
importable from `web_api` (public and the two externally-used private helpers)
is still importable from it.

**Acceptance Scenarios**:

1. **Given** the full list of symbols imported from `web_api` across the codebase
   (`graph`, `analyze_all`, `analyze`, `list_tasks`, `health`, `is_run_all_task`,
   `WebApiError`, `ERROR_INVALID_LANGUAGE`, `_solidity_file_import_paths`,
   `_rust_collect_module_links`), **When** imported from `web_api` after the
   refactor, **Then** all resolve.
2. **Given** web_api.py after the refactor, **When** its line count is measured,
   **Then** it is a thin facade (substantially smaller than 1485 lines) containing
   no bundle-assembly business logic of its own.

---

### Edge Cases

- **Externally-imported private helpers**: `_solidity_file_import_paths` (used by
  other modules/tests) and `_rust_collect_module_links` must remain importable
  from `web_api` even though they are underscore-prefixed. They move with their
  cluster but are re-exported.
- **Error identity**: `WebApiError` and `ERROR_INVALID_LANGUAGE` (and any other
  error sentinels) must remain the same objects from the caller's perspective, so
  `except web_api.WebApiError` and equality checks still match.
- **Circular imports**: extracted modules must not create an import cycle with
  `web_api`, `history_service`, or the adapters.
- **No new public surface**: the refactor must not add or remove any
  publicly-callable function; it only relocates implementations.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST preserve every public function currently exposed by
  `web_api` (`health`, `list_tasks`, `analyze`, `analyze_all`, `graph`,
  `is_run_all_task`) with identical signatures, return shapes, and error
  behaviour.
- **FR-002**: The system MUST keep every symbol currently imported from
  `web_api` by any other module or test importable from `web_api` after the
  refactor — including the error sentinels (`WebApiError`,
  `ERROR_INVALID_LANGUAGE`) and the externally-used private helpers
  (`_solidity_file_import_paths`, `_rust_collect_module_links`).
- **FR-003**: The system MUST relocate the bundle-graph assembly helpers (the
  Solidity/C/Rust `_attach_*`, `_resolve_*`, `_consolidate_*`, `_revalidate_*`,
  and supporting bundle helpers) into a dedicated module whose sole
  responsibility is graph/bundle assembly.
- **FR-004**: The system MUST relocate the task-catalog logic (`list_tasks`,
  `is_run_all_task`, and their supporting data) into a dedicated module.
- **FR-005**: The system MUST keep the analyze/graph orchestration facade
  (`analyze`, `analyze_all`, `graph`, `health`) as a clearly-scoped unit distinct
  from graph assembly and the task catalog.
- **FR-006**: The refactor MUST NOT change any rule output, finding, JSON
  response shape, or graph payload for any existing fixture (Solidity, C, Rust;
  single-file and bundle).
- **FR-007**: The system MUST NOT require edits to any caller file outside
  `services/web_api.py` and the newly created modules (no import-statement
  changes in routes, CLI, benchmark, adapters, or existing tests).
- **FR-008**: The extracted modules MUST NOT introduce import cycles.
- **FR-009**: `web_api.py` MUST end as a thin facade containing no
  bundle-assembly business logic of its own, only re-exports plus any minimal glue.

### Key Entities

- **Graph/bundle assembly module**: owns multi-file bundle edge construction and
  graph consolidation/revalidation for all three languages.
- **Task catalog module**: owns the enumerable audit-task list and the run-all
  task predicate.
- **Analyze facade**: owns request-level orchestration (validate target/mode,
  resolve language, run analysis, shape the report) and delegates graph work to
  the assembly module.
- **web_api facade module**: the stable public entry point; re-exports the above.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The full test suite passes with the same count as before the
  refactor (≥ 486 passed, 0 failed), with no test file modified to accommodate
  the move.
- **SC-002**: Graph payloads and JSON responses for all existing Solidity, C, and
  Rust fixtures (single-file and bundle) are byte-for-byte identical before and
  after the refactor.
- **SC-003**: `web_api.py` is reduced to a thin facade — its line count drops by
  at least 70% versus the current ~1485 lines.
- **SC-004**: Each new module has a single, nameable responsibility (graph/bundle
  assembly, task catalog, or analyze facade) and contains no code belonging to
  the others.
- **SC-005**: Zero import-statement changes are required in any caller file
  outside `services/web_api.py` and the new modules (verifiable by diff).

## Assumptions

- The existing test suite (unit + integration + golden + serializer + task-coverage
  manifests) is sufficient as the behavioural safety net; new tests are added only
  to lock the facade re-export contract, not to re-test relocated logic.
- "No behaviour change" is defined at the public boundary (function outputs, JSON
  shapes, graph payloads, error identities); internal helper signatures may be
  renamed/moved as long as the public boundary is preserved.
- Renderer unification (CLI graphviz vs web cytoscape) and structural graph diff
  are explicitly out of scope and handled as separate block-D features.
- The bundle-assembly cluster can be moved as a cohesive unit because its only
  external consumers are `web_api` itself plus the two re-exported private helpers.
