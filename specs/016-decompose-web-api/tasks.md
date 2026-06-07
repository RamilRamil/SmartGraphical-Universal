---
description: "Task list for feature 016 — Decompose the web_api god-module"
---

# Tasks: Decompose the web_api god-module

> **Status (2026-06-06): COMPLETE.** All 25 tasks done. `web_api.py` 1485 → 54
> lines (−96%). Full suite **493 passed** (486 baseline + 7 new facade-contract
> tests), 0 failed. Two honest notes:
> 1. **4 new modules, not 3.** A cycle was discovered: `task_catalog.list_tasks`
>    needs `WebApiError`/`ERROR_*`/`_build_service_safe`, while `analyze_facade`
>    needs `task_catalog.META_TASK_ALL_ID`. Resolved by extracting the shared
>    error contract + safe service/language wrappers into a foundational
>    `web_support.py` (imports only `cli.main`). Final layering:
>    `web_api → analyze_facade → {bundle_graph, task_catalog} → web_support`,
>    fully acyclic.
> 2. **Pre-existing taint nondeterminism found (NOT from this refactor).** The
>    SC-002 snapshot oracle differed only inside `tainted_input_unguarded_sink`
>    findings on `CollateralStateFixture.sol`: sink name/line vary with
>    `PYTHONHASHSEED` (feature 015 iterates a set of tainted names). The taint
>    code is byte-identical pre/post refactor; all graph payloads and every other
>    fixture matched, and the suite is green. Flagged as a separate latent bug.

**Input**: Design documents from `specs/016-decompose-web-api/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/facade.md, quickstart.md

**Tests**: This is a behaviour-preserving refactor. The existing suite (486
passing) + golden/serializer/contract + 3 task-coverage manifests are the safety
net. Only ONE new test is added — a facade re-export contract test (Principle VII
+ FR-002). Relocated logic is NOT re-tested (it is moved verbatim).

**Hard rule for every task**: move code **verbatim** (same names, bodies,
underscores). No renames, no signature changes, no logic edits. Do NOT touch any
caller file outside the new modules + `web_api.py` (FR-007). Do NOT touch
`interfaces/cli/main.py` (cycle guard — research Decision 2).

**Paths** are relative to `SmartGraphical/`. Run python as `.venv/bin/python`.

---

## Phase 1: Setup (baseline & safety net)

- [X] T001 Confirm baseline: run `.venv/bin/python -m pytest -q` and record the
  count (expect 486 passed, 11 skipped); run `wc -l smartgraphical/services/web_api.py`
  and record the baseline (~1485) for the SC-003 size check.
- [X] T002 Capture the pre-refactor snapshot per `quickstart.md` §0 into
  `/tmp/web_api_baseline.json` (graph + analyze_all + list_tasks for the
  Solidity `WithdrawNoGuard.sol` and C `TaintedFlow.c` fixtures; add a Rust
  fixture + a bundle root if present in the tree). This is the SC-002 oracle.
- [X] T003 Re-confirm the no-cycle constraint: `grep -n "web_api" smartgraphical/interfaces/cli/main.py`
  shows cli.main does NOT import web_api (only the documented duplication comment).
  Record that cli.main must stay untouched.

---

## Phase 2: Foundational (create empty module shells)

**Purpose**: create the three new module files so extraction tasks only move code.

- [X] T004 [P] Create `smartgraphical/services/bundle_graph.py` with a module
  docstring ("Multi-file bundle graph assembly for Solidity/C/Rust — relocated
  from web_api, feature 016") and the stdlib imports the moved code needs
  (`re`, `os`, `from pathlib import PurePosixPath`) plus the adapter/serializer
  imports it will use (`_clean`, `_strip_rust_comments`, and the serializer
  helpers actually referenced by the bundle code). Leave the body empty for now.
- [X] T005 [P] Create `smartgraphical/services/task_catalog.py` with a docstring
  and the imports `list_tasks` needs (adapter rule registries via
  `web_api`'s current imports, `interfaces.cli.main` language resolution as used
  today). Empty body for now.
- [X] T006 [P] Create `smartgraphical/services/analyze_facade.py` with a docstring
  and the imports the facade needs (`hashlib`, `json`, `os`, `time`; serializers;
  `analysis_service`/service builder; `interfaces.cli.main` `ALLOWED_MODES`,
  `_build_service`, `_resolve_language`). Empty body for now.

**Checkpoint**: `.venv/bin/python -c "import smartgraphical.services.bundle_graph, smartgraphical.services.task_catalog, smartgraphical.services.analyze_facade"`
imports cleanly (empty modules); suite still green.

---

## Phase 3: User Story 1 — Bundle-graph assembly in its own module (P1) 🎯 MVP

**Goal**: Relocate the bundle-graph assembly cluster (~lines 46–1191 of web_api.py)
into `bundle_graph.py`; `web_api.py` imports the moved names so all current
call sites keep working.

**Independent test**: full suite green + T002 snapshot still byte-identical for
the graph payloads.

- [X] T007 [US1] Move the bundle regex constants (`_RE_C_BUNDLE_INC_QUOTED`,
  `_RE_C_BUNDLE_INC_ANGLE`, `_RE_SOL_IMPORT`, `_RE_RUST_MOD_HEAD`,
  `_RE_RUST_USE_CRATE`, `_RE_RUST_USE_SUPER`, `_RE_SOL_CONTRACT_IS`) and
  `BUNDLE_MANIFEST_BASENAME` from `web_api.py` into `bundle_graph.py`.
- [X] T008 [US1] Move the Solidity bundle helpers verbatim into `bundle_graph.py`:
  `_solidity_same_basename_count`, `_resolve_solidity_provider_rel`,
  `_normalize_manifest_solidity_remappings`, `_apply_solidity_remappings`,
  `_strip_solidity_block_comments`, `_solidity_strip_line_comment`,
  `_solidity_clause_to_paths`, `_solidity_contract_inheritance_pairs`,
  `_solidity_file_import_paths`, `_solidity_member_contract_funcs`,
  `_consolidate_solidity_bundle_graph`, `_attach_solidity_bundle_import_edges`,
  `_attach_solidity_bundle_inheritance_edges`,
  `_attach_solidity_bundle_inherited_call_edges`.
- [X] T009 [US1] Move the C bundle helpers verbatim into `bundle_graph.py`:
  `_c_same_basename_count`, `_normalize_manifest_c_include_prefixes`,
  `_resolve_c_provider_rel`, `_c_bundle_collect_local_includes`,
  `_find_c_bundle_tile_id`, `_attach_c_bundle_include_edges`.
- [X] T010 [US1] Move the Rust bundle helpers verbatim into `bundle_graph.py`:
  `_resolve_rust_mod_provider_rel`, `_resolve_rust_super_provider_rel`,
  `_rust_crate_root_dirs`, `_rust_pick_crate_root_for_consumer`,
  `_rust_member_pool_for_crate_root`, `_resolve_rust_crate_provider_rel`,
  `_rust_naive_match_brace`, `_rust_collect_file_module_declarations`,
  `_rust_collect_module_links`, `_attach_rust_bundle_module_edges`.
- [X] T011 [US1] Move the shared/graph-generic bundle helpers verbatim into
  `bundle_graph.py`: `_touch_bundle_stat`, `_apply_bundle_edge_hints`,
  `_bundle_members_rel_set`, `_function_node_ids_by_type`,
  `_line_numbers_for_pattern`, `_type_node_ids_by_label`,
  `_inheritance_target_ids`, `_first_type_anchor_id`,
  `_external_import_path_node_id`, `_ensure_external_import_path_node`,
  `_bundle_import_dedupe`, `_revalidate_bundle_graph`.
- [X] T012 [US1] In `web_api.py`, replace the removed definitions with explicit
  imports from `bundle_graph` for every name still referenced by the remaining
  facade code AND every name re-exported externally (esp.
  `_solidity_file_import_paths`, `_rust_collect_module_links`). Resolve any
  cross-module constant use (e.g. `BUNDLE_MANIFEST_BASENAME` now imported back
  into web_api if the validation code still needs it).
- [X] T013 [US1] Verify US1: `.venv/bin/python -m pytest -q` green at the baseline
  count; re-run the snapshot (quickstart §2) and `diff` against
  `/tmp/web_api_baseline.json` → IDENTICAL.

**Checkpoint**: bundle assembly fully lives in `bundle_graph.py`; suite green;
graph payloads identical. MVP delivered.

---

## Phase 4: User Story 2 — Task catalog & analyze facade separated (P2)

**Goal**: Relocate the task catalog into `task_catalog.py` and the analyze/health
orchestration + error contract into `analyze_facade.py`.

**Independent test**: full suite green (incl. the 3 task-coverage manifest tests
and the HTTP contract tests); snapshot still identical.

- [X] T014 [US2] Move `META_TASK_ALL_ID`, `is_run_all_task`, and `list_tasks`
  verbatim into `task_catalog.py`. In `web_api.py`, import them back.
- [X] T015 [US2] Move the error contract verbatim into `analyze_facade.py`:
  `ERROR_INVALID_PATH`, `ERROR_INVALID_LANGUAGE`, `ERROR_INVALID_TASK`,
  `ERROR_INVALID_MODE`, `ERROR_INTERNAL`, and `class WebApiError`.
- [X] T016 [US2] Move the validation/orchestration helpers verbatim into
  `analyze_facade.py`: `_validate_analysis_target`, `_bundle_member_abs_paths`,
  `_analysis_source_steps`, `_is_bundle_root`, `_analyze_source`,
  `_assert_consistent_bundle_language`, `_validate_mode`, `_resolve_language_safe`,
  `_build_service_safe`, `_base_report`.
- [X] T017 [US2] Move the facade functions verbatim into `analyze_facade.py`:
  `health`, `analyze`, `analyze_all`, `graph`. Wire their internal calls to use
  `bundle_graph.*` and `task_catalog.*` (import those modules in
  `analyze_facade.py`; one-way deps only, never importing `web_api`).
- [X] T018 [US2] Verify US2: `.venv/bin/python -m pytest -q` green at baseline
  count; snapshot diff still IDENTICAL.

**Checkpoint**: task catalog and analyze facade each in their own module; suite
green; payloads identical.

---

## Phase 5: User Story 3 — web_api.py is a thin, documented facade (P3)

**Goal**: `web_api.py` contains no business logic — only explicit re-exports +
`__all__`, preserving every public symbol and the two private helpers. Lock it
with a test.

**Independent test**: facade re-export test passes; no caller import changed;
size dropped ≥70%.

- [X] T019 [US3] Reduce `web_api.py` to a thin facade: keep the module docstring;
  explicit `from .analyze_facade import (...)`, `from .task_catalog import (...)`,
  `from .bundle_graph import (...)` covering every symbol in
  `contracts/facade.md` (public functions, `WebApiError`, all `ERROR_*`,
  `is_run_all_task`, `_solidity_file_import_paths`, `_rust_collect_module_links`);
  add `__all__` listing the public surface. Ensure no orphaned/duplicate
  definitions remain.
- [X] T020 [US3] Add `tests/unit/test_web_api_facade_reexports.py`: assert every
  symbol in `contracts/facade.md` is importable from
  `smartgraphical.services.web_api`; assert `web_api.WebApiError is
  analyze_facade.WebApiError` (identity), and that `web_api.ERROR_INVALID_LANGUAGE`
  equals the owning-module value. Keep it pure/offline.
- [X] T021 [US3] Verify US3: run the new test + full suite green; confirm
  `web_api.WebApiError` still catches errors raised by relocated facade code
  (e.g. `analyze(<bad path>)` raises `web_api.WebApiError` with `ERROR_INVALID_PATH`).

**Checkpoint**: web_api is a thin facade; re-export contract locked by a test.

---

## Phase 6: Polish & cross-cutting verification

- [X] T022 [P] SC-003 size check: `wc -l smartgraphical/services/web_api.py` is
  ≤ ~445 lines (≥70% drop from ~1485).
- [X] T023 [P] SC-005 no-caller-drift check (quickstart §4): `git diff --name-only`
  shows only the 3 new modules + `web_api.py` + the new test under the feature's
  source scope (the pre-existing specs/005,008,010,012 + frontend WIP are
  unrelated and excluded).
- [X] T024 [P] SC-004 responsibility check: skim each new module to confirm it
  holds only its own concern (no facade code in bundle_graph, no bundle code in
  task_catalog, etc.).
- [X] T025 Final regression: `.venv/bin/python -m pytest -q` green at the
  baseline count; final snapshot diff IDENTICAL. Mark tasks [X] and add a status
  note to this file.

---

## Dependencies & ordering

- **Setup (T001–T003)** → first.
- **Foundational (T004–T006)** → after Setup; blocks all user stories (modules
  must exist before code moves into them). T004/T005/T006 are [P] (different files).
- **US1 (T007–T013)** → after Foundational. T008/T009/T010/T011 touch the same two
  files (`bundle_graph.py` + `web_api.py`) so run sequentially, not [P].
- **US2 (T014–T018)** → after US1 (US2's `analyze_facade` calls `bundle_graph`).
- **US3 (T019–T021)** → after US2 (facade re-exports everything once relocated).
- **Polish (T022–T025)** → after US3. T022/T023/T024 are [P] (independent checks).

## Implementation strategy

- **MVP = US1** (Phase 1–3): the largest cluster extracted, suite green, graph
  payloads byte-identical. Delivers the readability win + the clean graph seam
  the next block-D features need, even if US2/US3 are deferred.
- Incremental: US2 then US3 complete the single-responsibility goal and the thin
  facade. The snapshot diff + full suite run after every story keep the
  "no observable change" guarantee continuously enforced.
