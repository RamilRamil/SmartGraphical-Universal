---
description: "Task list for feature 013 — Finding Verdicts (false-positive / triage suppression)"
---

# Tasks: Finding Verdicts (False-Positive / Triage Suppression)

**Input**: Design documents from `specs/013-findings-fp-suppression/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED (constitution Principle VII; the spec asks for persistence,
key-stability, default-hide, and diff tests).

**Repo root**: `SmartGraphical/`. Backend runs with `.venv/bin/python` (system
python is 3.9). Frontend from `frontend/`.

## Implementation status (2026-06-02)

**Implemented + verified** (backend fully; frontend static-only): Foundational
(T002–T005), US1 (T006, T008, T009), US2 enrichment + frontend (T010–T014),
US3 carry-across-rescan test (T015), US4 diff (T016–T018), US5 controls (T019),
regression (T021). Backend: **451 pytest passed** (+15 new). Frontend: typecheck
clean, **76 vitest**, `npm run build` ok.

- **T007 — N/A**: verdicts are HistoryService operations surfaced **directly** by
  the HTTP routes (like `get_scan`/`diff_scans`); no `web_api` analysis-facade
  wrapper is needed. (web_api facade is for analyze/graph/tasks.)
- **Remaining**: T020 manual US5 round-trip in the running app, T022 docs
  (README/KNOWN_QUIRKS), and a small cosmetic CSS pass for the verdict badge/row.
  Visual checks (hide/reveal, set/clear) need `docker compose up --build`.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: parallelizable (different files, no dependency on incomplete tasks)
- **[Story]**: US1–US5 from spec.md

---

## Phase 1: Setup

- [X] T001 Baseline: `.venv/bin/python -m pytest -q` and (from `frontend/`) `npm run test && npm run typecheck` are green before changes.

---

## Phase 2: Foundational (Blocking Prerequisites)

**⚠️ Shared by all user stories: identity key, storage, repository.**

- [X] T002 Add the `finding_verdict` table + `idx_finding_verdict_artifact` index to `smartgraphical/persistence/schema.sql` per data-model.md (additive `CREATE TABLE IF NOT EXISTS`; `UNIQUE(artifact_id, finding_key)`, FK to `artifact` ON DELETE CASCADE). Auto-applied by `SqliteStore._apply_schema`.
- [X] T003 In `smartgraphical/services/history_service.py`, add `_finding_key_hash(finding)` = `sha256("\x00".join(_finding_key(finding))).hexdigest()`, keeping `_finding_key` as the single shared identity (diff + verdicts).
- [X] T004 Create `smartgraphical/persistence/verdict_repository.py` — `VerdictRepository` with `upsert(artifact_id, finding_key, status, note)`, `get_by_artifact(artifact_id)`, `delete(artifact_id, finding_key)`; construct it where `ScanRepository`/`ArtifactRepository` are wired and pass into `HistoryService`.
- [X] T005 [P] Tests `tests/unit/test_verdict_repository.py`: upsert inserts then overwrites (UNIQUE(artifact_id, finding_key)), `get_by_artifact` returns rows, `delete` removes, cascade on artifact delete.

**Checkpoint**: stable key + persistent store ready.

---

## Phase 3: User Story 1 - Record a verdict (Priority: P1) 🎯 MVP

**Goal**: set/clear a finding's verdict (false_positive | accepted) with a note; it persists.

**Independent Test**: `PUT` a verdict, `GET` it back; invalid status rejected.

- [X] T006 [US1] Add `set_verdict / clear_verdict / list_verdicts` to `HistoryService` (validate `status ∈ {false_positive, accepted}`; require existing artifact; upsert via `VerdictRepository`).
- [ ] T007 [US1] (N/A — verdicts call HistoryService directly via routes; no web_api facade needed) Add facade `set_verdict / clear_verdict / list_verdicts` to `smartgraphical/services/web_api.py` (pure, JSON-safe; `WebApiError` on invalid status / missing artifact) per contracts/verdict-api.md.
- [X] T008 [US1] Add routes to `smartgraphical/interfaces/http/routes.py` + schemas to `schemas.py`: `PUT /api/artifacts/{id}/verdicts`, `DELETE /api/artifacts/{id}/verdicts/{finding_key}`, `GET /api/artifacts/{id}/verdicts`.
- [X] T009 [US1] Tests: `tests/unit/test_history_service_verdicts.py` (set/get/clear, invalid status) and `tests/integration/test_http_verdicts.py` (endpoint contract + 400 on bad status, 404 on missing artifact).

**Checkpoint**: verdicts can be recorded and read via the API.

---

## Phase 4: User Story 2 - Hide suppressed noise (Priority: P1)

**Goal**: false-positive findings hidden by default with a "N suppressed" toggle; active count excludes them; accepted findings marked.

**Independent Test**: a scan with K false-positives shows N−K by default; toggle reveals K.

- [X] T010 [US2] Enrich findings in `HistoryService.get_scan` and `get_findings`: attach `finding_key` (= `_finding_key_hash`) and `verdict` (`{status, note}` or `null`) by looking up the scan's artifact verdicts once (map). Additive fields only.
- [X] T011 [P] [US2] Frontend `frontend/src/api/types.ts` + `hooks.ts` + `client.ts`: add `verdict`/`finding_key` to `Finding`, a `Verdict` type, and a set/clear verdict mutation that invalidates the scan query.
- [X] T012 [P] [US2] `frontend/src/components/FindingCard.tsx`: verdict controls (mark false-positive / accepted / clear, optional note) and a status marker; calls the mutation with `finding_key`.
- [X] T013 [US2] `frontend/src/pages/ScanDetailPage.tsx`: hide `false_positive` findings by default, add a "N suppressed" reveal toggle, exclude them from the active count, compose with the existing confidence filter.
- [X] T014 [US2] Verify US2: enrichment test asserts findings carry `finding_key`+`verdict`; manual quickstart §4 (hide/reveal/count).

**Checkpoint**: the findings list is quieter; the MVP (record + hide) is usable.

---

## Phase 5: User Story 3 - Verdicts survive a re-scan (Priority: P1)

**Goal**: a recurring finding keeps its verdict across re-scans (artifact-scoped, stable key).

**Independent Test**: mark FP, re-scan same artifact, finding still suppressed without re-marking.

- [X] T015 [US3] Test `tests/unit/test_history_service_verdicts.py` (add cases): the same finding across two scans of one artifact yields the same `_finding_key_hash` and the verdict applies to both; a verdict whose finding is absent in a scan is retained and inert (no error). Validates the foundational design; no new production code expected.

**Checkpoint**: triage is durable across runs.

---

## Phase 6: User Story 4 - Diff respects verdicts (Priority: P2)

**Goal**: a false-positive finding does not resurface as "added"; diff exposes `suppressed_count`.

- [X] T016 [US4] In `HistoryService.diff_scans`, load the artifact's `false_positive` verdict keys and drop matching findings from `added`/`removed`; add `suppressed_count` to the result (additive).
- [X] T017 [P] [US4] `frontend/src/pages/DiffPage.tsx` + `api/types.ts`: surface `suppressed_count` (e.g. "N suppressed by verdict"); buckets already exclude them.
- [X] T018 [US4] Test (in `test_history_service_verdicts.py`): a FP-verdicted finding present in both scans is absent from `added`; `suppressed_count` reflects it.

---

## Phase 7: User Story 5 - Change or clear a verdict (Priority: P3)

**Goal**: change a verdict, clear it back to untriaged, edit the note.

- [X] T019 [US5] Ensure `FindingCard` (T012) supports changing status (FP↔accepted), clearing to untriaged, and editing the note (re-`PUT` upserts; `DELETE` clears); no new backend beyond US1 endpoints.
- [ ] T020 [US5] Verify US5 per quickstart (change/clear/edit-note round-trips and persists).

---

## Phase 8: Polish & Cross-Cutting

- [X] T021 [P] Full regression: `.venv/bin/python -m pytest -q` (0 failed) and `frontend/` `npm run test && npm run typecheck` green; confirm no-verdict findings/graph/history/diff are unchanged (Principle VI).
- [ ] T022 [P] Docs: note finding verdicts + the shared `_finding_key` identity in `README.md`; add a `KNOWN_QUIRKS.md` entry if same-key findings sharing one verdict is worth recording.

---

## Dependencies & Execution Order

- **Setup (T001)** → none.
- **Foundational (T002–T005)** → blocks all stories (schema + key + repo).
- **US1 (T006–T009)** → after Foundational.
- **US2 (T010–T014)** → after Foundational + US1 (enrichment reads verdicts; frontend uses US1 endpoints). T011/T012 are parallel (different files); T013 depends on T010+T011.
- **US3 (T015)** → after Foundational + US1 (needs to set a verdict in the test). Verification-only.
- **US4 (T016–T018)** → after Foundational + US1.
- **US5 (T019–T020)** → after US1 + US2.
- **Polish (T021–T022)** → after all; parallel.

## Parallel Opportunities

- T011 (frontend types/hooks) and T012 (FindingCard) — different files.
- T017 (DiffPage) independent of the FindingCard work.
- T021 and T022 — independent checks/docs.

## Implementation Strategy

- **MVP = US1 + US2** (record a verdict + hide false positives) — the visible
  payoff; ship and validate before US3/US4/US5.
- **Persistence-first**: Foundational (table + key + repo) → US1 (record) →
  US2 (enrich + hide) → US3 (carry across re-scan, mostly a test) → US4 (diff)
  → US5 (edit/clear).
- Backend record path (US1) is testable headless before any UI exists.
