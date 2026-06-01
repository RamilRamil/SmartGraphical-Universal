---
description: "Task list for feature 011 — Adapter Contract, C/Rust Web Analysis, CI Gate"
---

# Tasks: Adapter Contract, Restored C/Rust Web Analysis, and CI Gate

**Input**: Design documents from `specs/011-adapter-contract-ci/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED for this feature — the spec explicitly asks for an adapter
conformance test (FR-003), a fully green suite (SC-002), and a CI gate (FR-006).

**Repo root for all paths**: `SmartGraphical/`. Run Python with `.venv/bin/python`
(system `python3` is 3.9 and too old).

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: can run in parallel (different files, no dependency on incomplete tasks)
- **[Story]**: which user story the task serves (US1, US2, US3)

---

## Phase 1: Setup

- [X] T001 Reproduce and record the baseline: run `.venv/bin/python -m pytest -q` and confirm `17 failed, 419 passed` (14 facade `expand_local_imports` + 3 non-facade), per `specs/011-adapter-contract-ci/quickstart.md` §1.

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ Blocks US1 and US2.**

- [X] T002 Create `smartgraphical/adapters/base.py` defining the `AnalysisAdapter` `typing.Protocol` with `parse_source(self, source_path: str, *, expand_local_imports: bool = True) -> AnalysisContext` (import `AnalysisContext` from `smartgraphical.core.model`); include the contract docstring covering rules R1–R5 from `specs/011-adapter-contract-ci/contracts/adapter-contract.md`.

**Checkpoint**: shared contract type exists; user stories can begin.

---

## Phase 3: User Story 1 - Restore C/Rust web analysis (Priority: P1) 🎯 MVP

**Goal**: C and Rust/Stellar files analyze through the web facade (single file and bundle) with no `TypeError`, returning findings + a correct graph — like Solidity.

**Independent Test**: the previously-failing C/Rust facade, bundle, and C-graph tests pass; manual `web_api.analyze_all('tests/fixtures/c/MinimalTu.c', language='c')` returns a report.

- [X] T003 [P] [US1] In `smartgraphical/adapters/c_base/adapter.py`, change `parse_source(self, source_path)` to `parse_source(self, source_path, *, expand_local_imports=True)`; ignore the flag (documented no-op — C has no local-import expansion yet) and add a docstring note.
- [X] T004 [P] [US1] In `smartgraphical/adapters/rust_stellar/adapter.py`, change `parse_source(self, source_path)` to `parse_source(self, source_path, *, expand_local_imports=True)`; ignore the flag (documented no-op) and add a docstring note.
- [X] T005 [US1] Fix the C include-template anchor in `smartgraphical/services/serializers.py` `model_graph_to_dict.resolve_endpoint` (~line 676): when `target_name == _TU_INCLUDE_EDGE_SOURCE` and `edge_kind == "function_to_include_template"`, resolve to the TU **tile** id (`tile:<label>`, see line 269) instead of `_type_id(...)` (`type:<label>`, line 177), so the edge originates from the TU tile and function nodes get `calls_include_template = True`.
- [X] T006 [US1] Verify US1: `.venv/bin/python -m pytest tests/unit/test_web_api_contract.py tests/integration/test_http_rust_fixture_contract.py tests/integration/test_http_contract.py tests/unit/test_c_adapter_model_graph.py -q` — all green (covers facade analyze/bundle for C+Rust and the two C include-template graph tests).

**Checkpoint**: the user-facing outage is fixed; MVP deliverable.

---

## Phase 4: User Story 2 - Enforce one adapter contract (Priority: P1)

**Goal**: all three adapters conform to `AnalysisAdapter`; signature drift is caught automatically and names the offender.

**Independent Test**: conformance test passes for all registered adapters; deliberately breaking one makes it fail naming the class.

- [X] T007 [US2] Create `tests/unit/test_adapter_contract_conformance.py`: for each registered adapter (`SolidityAdapterV0`, `CBaseAdapterV0`, `RustStellarAdapterV0`), assert via `inspect.signature` that `parse_source` accepts keyword `expand_local_imports` and requires no positional beyond `source_path`, and that calling it with `expand_local_imports=True` and `=False` on the matching `tests/fixtures/` file returns an `AnalysisContext` with non-null `normalized_model` (per `contracts/adapter-contract.md`).
- [X] T008 [US2] Reference the contract so it is not orphaned: annotate the three adapter classes / the language→adapter resolution (`web_api._build_service_safe` / `cli` `_resolve_language`) so each adapter is treated as an `AnalysisAdapter` (import from `smartgraphical/adapters/base.py`); no behavior change.
- [X] T009 [US2] Verify US2 per quickstart §3: conformance test passes; temporarily remove `expand_local_imports` from `c_base/adapter.py::parse_source`, confirm the test FAILS and names `CBaseAdapterV0`, then revert.

**Checkpoint**: the regression class is closed by an enforced, tested contract.

---

## Phase 5: User Story 3 - CI gate keeps the suite green (Priority: P2)

**Goal**: every push/PR runs the suite + a machine-readable CLI smoke and blocks on failure; the suite is fully green.

**Independent Test**: the workflow runs on push/PR and reports pass on a green tree and failure on a broken one.

- [X] T010 [US3] Update the stale Solidity golden in `tests/integration/test_solidity_adapter_fixtures.py::test_minimal_guard_phase5_shape_snapshot` so `state_entities` includes `amount` (the adapter now correctly detects it after spec 008); confirm `amount` is a legitimate state entity of `MinimalGuard` before changing the golden.
- [X] T011 [US3] Confirm the full suite is green: `.venv/bin/python -m pytest -q` reports `0 failed` (SC-002), per quickstart §6.
- [X] T012 [US3] Add `.github/workflows/ci.yml` per `specs/011-adapter-contract-ci/contracts/ci-workflow.md`: trigger on `push` + `pull_request`; matrix Python `3.10` and `3.12` on `ubuntu-latest`; steps install `requirements.txt` + pytest, run `python -m pytest -q`, then run `python sg_cli.py examples/SimpleAuction.sol all auditor --format json` and assert the stdout parses as JSON; fail the job on any failure.
- [X] T013 [US3] Validate the gate per quickstart §5: confirm the workflow passes on the green branch and that a deliberate failing test (scratch commit) is reported as a blocking failure; remove the scratch commit.

**Checkpoint**: green suite enforced automatically.

---

## Phase 6: Polish & Cross-Cutting Concerns

- [X] T014 [P] Update `README.md`: state three supported languages (Solidity, C/Solana, Rust/Stellar — not "Two languages"); add a short note that CI runs the suite + CLI JSON smoke on push/PR.
- [X] T015 [P] If the `tile:` (C TU) vs `type:` (Solidity) node-id duality is intentional, add a `KNOWN_QUIRKS.md` entry documenting the include-template anchor → `tile:` resolution rule (research.md D5, constitution Principle VII).
- [X] T016 [P] Update `NEXT_STEPS_PLAN.md`: mark "CI smoke run" delivered and record the shared adapter contract as the foundation for later features (B/C/D).

---

## Dependencies & Execution Order

- **Setup (T001)** → no dependencies.
- **Foundational (T002)** → after Setup; **blocks US1 and US2**.
- **US1 (T003–T006)** → after T002. T003 and T004 are parallel; T005 is independent of T003/T004 (different file); T006 verifies after T003–T005.
- **US2 (T007–T009)** → after T002. T007 (conformance) only turns green once US1's T003/T004 land, so schedule US2 after US1; T008 is independent; T009 verifies last.
- **US3 (T010–T013)** → after US1 + US2 (green suite needs all fixes). T010 reaches green, T011 confirms, T012 adds the gate, T013 validates.
- **Polish (T014–T016)** → after the suite is green; all parallel.

## Parallel Opportunities

- T003 and T004 together (`[P]`, different adapter files).
- T014, T015, T016 together (`[P]`, different docs).

## Implementation Strategy

- **MVP = US1**: ship T001→T006 first to end the user-facing C/Rust web outage; validate independently, then continue.
- **Incremental**: US1 (outage) → US2 (guard against recurrence) → US3 (automated gate) → Polish (docs/quirks).
- **Suggested first PR**: Foundational + US1 + US2 (fix + contract + conformance), so the suite is green and protected; CI (US3) can follow immediately after or in the same PR.
