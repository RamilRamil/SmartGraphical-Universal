# Implementation Plan: Go Language Audit Rules and Adapter

**Branch**: `019-go-language-rules` | **Date**: 2026-06-25 | **Spec**: [spec.md](spec.md)

## Summary

Wire the existing `docs/go_language_rules_catalog.json` (18 rules from Sigma Prime
Part 1) into a new Go adapter and rule runners. Use the same lexer-light approach
as C/Rust adapters: comment strip, brace-balanced function bodies, normalized
functions/types/call edges. Register `go` in CLI, `analyze_facade`, and upload
paths. Add fixture + contract tests; keep other languages unchanged.

## Technical Context

**Language/Version**: Python 3.10+ backend; Go sources analyzed as text.

**Dependencies**: stdlib only (regex). No `go` toolchain required in CI.

**Testing**: `pytest` via `.venv/bin/python -m pytest`.

**Catalog**: `docs/go_language_rules_catalog.json`, `docs/rules_ru_go.md`.

## Constitution Check

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing | PASS — regex/brace heuristics, no go/parser. |
| II. Auditor-Centric | PASS — medium/low confidence heuristics; human review expected. |
| III. Normalized Model | PASS — GoAdapterV0 returns AnalysisContext + model. |
| IV. Portability | PASS — fourth adapter on shared contract. |
| V. Two Pillars | PASS — graph from same normalized projection. |
| VI. Stable Contracts | PASS — additive language; existing APIs unchanged. |
| VII. Test Gates | PASS — conformance + fixture contract tests. |

## Project Structure

```text
specs/019-go-language-rules/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── tasks.md
├── quickstart.md
├── contracts/go-adapter.md
└── checklists/requirements.md

docs/go_language_rules_catalog.json   # registry_source updated
docs/rules_ru_go.md

smartgraphical/adapters/go/adapter.py
smartgraphical/core/rules/go/language_rules.py

tests/fixtures/go/GoViolations.go
tests/integration/test_http_go_fixture_contract.py
```

## Implementation Phases

1. **Rules** — `language_rules.py` with 18 `run_*` functions (grep-grade).
2. **Adapter** — extract func/method/struct; populate model; `build_go_rule_registry`.
3. **Wiring** — `cli/main.py`, `analyze_facade.py`, `history_service.py`.
4. **Tests** — adapter conformance, HTTP/CLI contract, fixture smoke.
5. **Docs** — Spec Kit artifacts + update workspace specify rule pointer.
