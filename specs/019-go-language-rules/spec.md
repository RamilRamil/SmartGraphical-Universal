# Feature Specification: Go Language Audit Rules and Adapter

**Feature Branch**: `019-go-language-rules`

**Created**: 2026-06-25

**Status**: In Progress

**Input**: Add a fourth SmartGraphical language target for Go (`.go`), with 18
heuristic audit rules derived from Sigma Prime "Go for Security Auditors: Part 1"
and the existing catalog at `docs/go_language_rules_catalog.json`.

## Context

SmartGraphical today supports Solidity, C/Solana, and Rust/Stellar. Go appears in
tests only as an *unknown* language. The project already documents 18 Go rules
(catalog + Russian descriptions) but has no adapter, runners, or web/CLI wiring.

This feature adds lexer-light Go extraction (regex + brace balancing, Principle I),
registers tasks **1-18** from the catalog, and exposes `go` through the same
facade paths as other languages. Graph rendering reuses the normalized model.

Governed by constitution Principles III (normalized model contract), IV
(portability), VI (stable JSON contracts), VII (green suite).

## User Scenarios & Testing

### User Story 1 - Analyze Go through CLI and web (Priority: P1)

An auditor uploads or points the CLI at a `.go` file and receives findings and a
graph without `invalid_language` errors.

**Independent Test**: `web_api.analyze(GoViolations.go, "1")` returns `status: ok`
and `language: go`; `GET /api/languages/go/tasks` lists meta task `0` and rules `1-18`.

### User Story 2 - Catalog-aligned rule runners (Priority: P1)

Each `rule_id` in `docs/go_language_rules_catalog.json` maps to one `RuleSpec` task
with a grep-grade runner in `core/rules/go/language_rules.py`.

**Independent Test**: fixture `tests/fixtures/go/GoViolations.go` triggers at least
one finding for tasks 4, 5, 7, 10, 16 when run individually; task `0` runs all 18.

### User Story 3 - Adapter contract conformance (Priority: P2)

`GoAdapterV0` implements `AnalysisAdapter.parse_source` like existing adapters.

**Independent Test**: `test_adapter_contract_conformance.py` includes Go case.

## Requirements

- **FR-001**: Register language id `go` in CLI, web facade `supported_languages`,
  and upload extension `.go`.
- **FR-002**: Implement `GoAdapterV0` returning populated `NormalizedAuditModel`.
- **FR-003**: Implement `build_go_rule_registry()` with tasks **1-18** matching catalog.
- **FR-004**: Do not change Solidity/C/Rust output for unchanged inputs.
- **FR-005**: Document feature under `specs/019-go-language-rules/` (Spec Kit).

## Out of Scope

- Full `go/parser` or `go/types` integration (Principle I).
- Part 2/3 Sigma Prime topics (entry-point navigation, vuln catalog) — future specs.
- Go multi-file bundle import graph (flag accepted as no-op).
