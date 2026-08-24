---
description: "Task list for feature 019 — Go language audit rules and adapter"
---

# Tasks: Go Language Audit Rules and Adapter

**Input**: `specs/019-go-language-rules/`  
**Catalog**: `docs/go_language_rules_catalog.json`

## Phase 1: Spec Kit & catalog

- [X] T001 spec.md, plan.md, research.md, data-model.md, contracts/, quickstart.md, checklists/
- [X] T002 Update catalog `registry_source` to `smartgraphical/adapters/go/adapter.py`

## Phase 2: Rule runners

- [X] T003 `smartgraphical/core/rules/go/language_rules.py` — 18 `run_*` heuristics
- [X] T004 `smartgraphical/core/rules/go/__init__.py`

## Phase 3: Adapter

- [X] T005 `smartgraphical/adapters/go/adapter.py` — parse + `build_go_rule_registry`
- [X] T006 Fixture `tests/fixtures/go/GoViolations.go`

## Phase 4: Wiring

- [X] T007 `cli/main.py` — `.go`, `_build_service("go")`
- [X] T008 `analyze_facade.py` — `supported_languages` includes `go`
- [X] T009 `history_service.py` — `.go` upload extension

## Phase 5: Tests

- [X] T010 Adapter conformance case for Go
- [X] T011 `tests/integration/test_http_go_fixture_contract.py`
- [X] T012 Update tests that treated `go` as invalid language
- [X] T013 Full suite green (519 passed, 2026-06-25)

## Phase 6: Workspace docs

- [X] T014 Update `.cursor/rules/specify-rules.mdc` pointer to 019 plan
- [X] T015 Mark tasks.md complete after pytest
