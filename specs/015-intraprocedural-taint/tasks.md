---
description: "Task list for feature 015 — Pragmatic intra-procedural taint / dataflow facts"
---

# Tasks: Pragmatic Intra-Procedural Taint / Dataflow Facts

> **Status (2026-06-05): COMPLETE.** All 17 tasks done. Full suite green
> (486 passed, 11 skipped). Two discoveries recorded honestly rather than
> hidden: (1) only 3 of the 5 `requires_dataflow` catalog rules have runners —
> the other 2 (`missing_snapshot_hash_verification`, `cross_tile_fseq_write`)
> are catalog-only and asserted as an explicit gap in
> `test_requires_dataflow_invoked.py` + KNOWN_QUIRKS Quirk 7. (2) The portable
> `tainted_input_unguarded_sink` rule is genuinely additive — it now fires on
> the Solidity withdraw/mint pipeline fixtures, so the pipeline allowlist and
> both `*_task_coverage.json` manifests were updated to declare the new rule.

**Input**: Design documents from `specs/015-intraprocedural-taint/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED (constitution Principle VII).

**Repo root**: `SmartGraphical/`. Backend runs with `.venv/bin/python` (system
python is 3.9). Pure Python analysis core — fully verifiable headless.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: parallelizable (different files, no dependency on incomplete tasks)
- **[Story]**: US1–US5 from spec.md

---

## Phase 1: Setup

- [X] T001 Baseline: `.venv/bin/python -m pytest -q` is green; note the 5 `requires_dataflow` rule slugs from `docs/c_node_rules_catalog.json` (for the US3 invocation test).

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ The taint field + pass + wiring back every story.**

- [X] T002 Add an additive `taint_paths: list = field(default_factory=list)` to `NormalizedFunction` in `smartgraphical/core/model.py` (default empty; consumers that ignore it are unaffected).
- [X] T003 Create `smartgraphical/core/dataflow/__init__.py` and `smartgraphical/core/dataflow/taint.py` with `compute_taint(function)`, `apply_taint(model)`, and the source/sink token constants per `contracts/taint.md` (pure, no AST).
- [X] T004 Wire `apply_taint(context.normalized_model)` into `smartgraphical/services/analysis_service.py::AnalysisService.analyze` after `adapter.parse_source(...)`, before returning — one seam for all languages.

**Checkpoint**: every analyzed function carries a (possibly empty) `taint_paths`.

---

## Phase 3: User Story 1 - Intra-procedural taint facts (Priority: P1) 🎯 MVP

**Goal**: per function, untrusted source -> sensitive sink reachability with a guarded flag.

**Independent Test**: unguarded flow recorded; guarded flagged; no-flow empty; deterministic.

- [X] T005 [US1] Implement `compute_taint` in `smartgraphical/core/dataflow/taint.py`: seed `tainted` from `function.inputs`; walk `exploration_statements` (fall back to `body`); propagate across assignments and untrusted-read sources; detect sinks (mutations + sink tokens); set `guarded` from `guard_facts` / require/if/assert before the sink; bounded + deterministic per data-model.md.
- [X] T006 [US1] Tests `tests/unit/test_taint_pass.py` (synthetic `NormalizedFunction`s): unguarded source->sink yields a `taint_path` with `guarded=False`; a guard yields `guarded=True`; no-flow yields `[]`; two runs identical.

**Checkpoint**: taint facts exist and are tested — MVP foundation.

---

## Phase 4: User Story 2 - Portable "tainted input -> unguarded sink" rule (Priority: P1)

**Goal**: a medium-confidence finding per unguarded tainted flow, on C and Solidity.

**Independent Test**: fires on the unguarded fixture; silent on guarded / no-flow.

- [X] T007 [US2] Create `smartgraphical/core/rules/portable/__init__.py` and `tainted_input_unguarded_sink.py`: `run(context)` emits one `confidence='medium'` finding per `function.taint_paths` entry with `guarded == False`, evidence = source_stmt + sink_stmt.
- [X] T008 [US2] Register the portable rule in `smartgraphical/adapters/solidity/adapter.py` and `smartgraphical/adapters/c_base/adapter.py` rule registries under the next free task id in each.
- [X] T009 [P] [US2] Add fixtures: `tests/fixtures/c/TaintedFlow.c` with an unguarded tainted source->sink and a guarded variant (and a Solidity fixture if the normalized facts support it).
- [X] T010 [US2] Tests `tests/unit/test_tainted_input_rule.py`: the rule emits exactly one medium-confidence finding (with source+sink evidence) on the unguarded fixture, and is silent on the guarded and no-flow cases.

**Checkpoint**: dataflow produces a finding end-to-end — MVP deliverable.

---

## Phase 5: User Story 3 - `requires_dataflow` rules are invoked (Priority: P2)

**Goal**: prove the 5 catalog `requires_dataflow` rules execute (not skipped) and that taint facts are additive.

**Independent Test**: each rule is registered and runs without error; their output is unchanged by adding taint facts.

- [X] T011 [US3] Test `tests/unit/test_requires_dataflow_invoked.py`: enumerate the 5 `requires_dataflow` rules; assert each is in the C rule registry and its `run(context)` completes without error on a C fixture (0 silently skipped, SC-002); assert their findings are unchanged whether or not `taint_paths` is populated (additive).

**Checkpoint**: the dataflow rules are demonstrably live and unaffected.

---

## Phase 6: User Story 4 - Honest, hypothesis-level output (Priority: P2)

**Goal**: medium ceiling + documented heuristic limits.

- [X] T012 [US4] Add a `KNOWN_QUIRKS.md` entry: intra-procedural only, token-match false positives, aliasing/cross-function false negatives, medium-confidence ceiling.
- [X] T013 [US4] Assert (in `test_tainted_input_rule.py`) that the portable rule's finding confidence is exactly `"medium"` (never higher) — FR-006/SC-004.

---

## Phase 7: User Story 5 - Explain why a finding fired (Priority: P3)

**Goal**: exploration output lists a function's source->sink paths.

- [X] T014 [US5] Surface `taint_paths` in exploration output (extend `summarize_model` / explore mode in `smartgraphical/core/engine.py` or the CLI explore path) — list source, sink, guarded per function.
- [X] T015 [US5] Verify per quickstart §5 (explore output shows the path).

---

## Phase 8: Polish & Cross-Cutting

- [X] T016 [P] Full regression: `.venv/bin/python -m pytest -q` (0 failed); confirm non-taint rule/finding output is unchanged (SC-005) and no dataflow finding exceeds medium.
- [X] T017 [P] Docs: note the delivered intra-procedural dataflow phase in `NEXT_STEPS_PLAN.md`; cross-reference the `requires_dataflow` catalog flag.

---

## Dependencies & Execution Order

- **Setup (T001)** → none.
- **Foundational (T002→T003→T004)** → blocks all stories.
- **US1 (T005→T006)** → after Foundational.
- **US2 (T007–T010)** → after US1 (rule reads `taint_paths`). T009 fixtures [P].
- **US3 (T011)** → after Foundational (independent of US1/US2 logic).
- **US4 (T012–T013)** → after US2.
- **US5 (T014–T015)** → after US1.
- **Polish (T016–T017)** → after all; parallel.

## Parallel Opportunities

- T009 (fixtures) alongside T007/T008.
- T016 and T017 — independent.

## Implementation Strategy

- **MVP = Foundational + US1 + US2** (taint facts + portable rule firing on a
  fixture) — the first real dataflow capability; ship and review before US3–US5.
- **Pass-first**: `taint.py` is unit-tested in isolation; the rule, the
  invocation guard, and exploration are thin consumers. All Python — fully
  verifiable headless.
