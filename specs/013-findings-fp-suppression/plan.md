# Implementation Plan: Finding Verdicts (False-Positive / Triage Suppression)

**Branch**: `013-findings-fp-suppression` | **Date**: 2026-06-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/013-findings-fp-suppression/spec.md`

## Summary

A persistent triage layer over findings: the auditor marks a finding
`false_positive` or `accepted` (with a note); false positives are hidden by
default and excluded from counts and from the diff's "added" bucket; verdicts
carry across re-scans of the same artifact. No rules/parsing change.

Decisive grounding (from the code):
- The diff already derives a stable per-finding key,
  `_finding_key(finding) = (rule_id, type_name, function_name,
  source_statement|statement, message)` (`history_service.py:155`), used in
  `diff_scans` (`:487`). This is the single identity source we reuse — a stable
  string **hash** of that same tuple keys a verdict.
- `SqliteStore._apply_schema()` runs `schema.sql` via `executescript` on every
  init (`sqlite_store.py:51`, idempotent `CREATE ... IF NOT EXISTS`), so adding a
  `finding_verdict` table is an additive auto-migration.
- Findings reach the UI through `HistoryService.get_scan` / `get_findings`
  (`:435` / `:466`, which `_read_json` the per-scan findings) and the routes
  `GET /api/scans/{id}` and `/findings`. Those are the enrichment points where
  each finding gains `finding_key` + `verdict`.

## Technical Context

**Language/Version**: Python 3.10+ (backend); React + TypeScript (frontend).

**Primary Dependencies**: existing only — SQLite via `SqliteStore`, FastAPI
routes, the `web_api` facade, TanStack Query + React on the frontend. No new
dependency.

**Storage**: SQLite. One additive table `finding_verdict` (artifact-scoped),
applied via the existing idempotent `schema.sql` bootstrap.

**Testing**: Python `unittest`/pytest (repository + history-service + facade +
HTTP contract); optional Vitest for the frontend filter logic.

**Target Platform**: local web app (FastAPI + static frontend on :8765).

**Project Type**: web service + frontend (single backend package + `frontend/`).

**Performance Goals**: verdict lookup for a scan is O(findings) with an indexed
read of the artifact's verdicts; no perceptible delay on the findings list.

**Constraints**: additive schema + additive finding fields; reuse the ONE diff
key (no second identity scheme); the tool never auto-sets a verdict; existing
findings/graph/history/diff behavior unchanged when no verdict exists.

**Scale/Scope**: one table, one repository, ~3 history-service methods + 2
enrichment points + diff filter, ~3 facade/HTTP endpoints, frontend verdict
controls + default-hide filter.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after design.*

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing Over Full AST | PASS — no parsing/AST work. |
| II. Auditor-Centric, Human-in-the-Loop | DIRECTLY SERVES — records the auditor's verdict only; never auto-suppresses; keeps triage across runs. |
| III. Normalized Model Is the Contract | PASS — no adapter/model change; operates on emitted findings. |
| IV. Portability Across Languages | PASS — verdicts are language-agnostic (over findings of any language). |
| V. Two Pillars Stay Connected | PASS — verdicts annotate findings by the same identity the graph overlay (012) resolves; a future graph-respects-verdicts tie-in is noted as out of scope, no divergence introduced. |
| VI. Stable, Machine-Readable Contracts | DIRECTLY SERVES — additive table + additive `finding_key`/`verdict` fields; reuses the single diff key so suppression and diff agree; scan delete never deletes verdicts. |
| VII. Test & Traceability Gates | PASS — tests for persistence, key stability across re-scan, default-hide, and diff interaction. |

**Result**: No violations. Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/013-findings-fp-suppression/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 decisions
├── data-model.md        # finding_verdict table + enriched finding shape
├── contracts/
│   └── verdict-api.md    # HTTP + web_api facade + finding-enrichment contract
├── quickstart.md
└── checklists/requirements.md  # all passed
```

### Source Code (repository root = `SmartGraphical/`)

```text
smartgraphical/
├── persistence/
│   ├── schema.sql                  # ADD: finding_verdict table (+ index)
│   └── verdict_repository.py       # NEW: upsert / get_by_artifact / delete
└── services/
    ├── history_service.py          # ADD: _finding_key_hash; set/clear/list_verdict;
    │                               #      enrich get_scan/get_findings; diff filter
    └── web_api.py                  # ADD: set_verdict/clear_verdict/list_verdicts facade
└── interfaces/http/
    ├── routes.py                   # ADD: PUT/DELETE/GET verdict routes
    └── schemas.py                  # ADD: verdict request/response shapes

frontend/src/
├── api/{types.ts,hooks.ts,client.ts}   # ADD: Verdict types + set/clear mutations
├── components/FindingCard.tsx          # ADD: verdict controls + marker
└── pages/ScanDetailPage.tsx            # default-hide FP + "N suppressed" toggle + active count

tests/
├── unit/test_verdict_repository.py         # NEW
├── unit/test_history_service_verdicts.py   # NEW: set/get/clear, key stability, diff
└── integration/test_http_verdicts.py       # NEW: endpoint contract
```

**Structure Decision**: mirror the existing persistence/service/facade/route
layering (a `VerdictRepository` alongside `ScanRepository`/`ArtifactRepository`;
verdict methods on `HistoryService`; thin facade + routes). The stable key lives
once in `history_service` and is shared by diff and verdicts.

## Phase Overview

- **Phase 0 (research.md)**: stable-key hash decision, table shape + additive
  migration, enrichment points, diff-filtering rule, repository pattern, frontend
  wiring.
- **Phase 1 (data-model.md + contracts/ + quickstart.md)**: the `finding_verdict`
  entity, enriched finding fields, the verdict API contract, validation steps;
  update agent context.
- **Phase 2 (/speckit.tasks)**: tasks per user story (US1 record, US2 hide, US3
  carry-across-rescan, US4 diff, US5 edit/clear), persistence-first.

## Complexity Tracking

No constitution violations — no entries.
