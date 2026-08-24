# Research: Go Language Audit Rules

**Feature**: 019-go-language-rules | **Date**: 2026-06-25

## Source Material

Sigma Prime, *Go for Security Auditors: Part 1 - Syntax That Will Trip You Up*
(June 2026). Mapped 1:1 to catalog rule ids in `docs/go_language_rules_catalog.json`.

## Parsing Approach

**Decision**: Regex + brace balancing (same tier as `c_base` / `rust_stellar`).

**Rationale**: Constitution Principle I forbids heavy parser deps; Go audit heuristics
target idiomatic patterns visible in source text.

**Alternatives rejected**:
- `go/parser` via subprocess — requires Go toolchain in CI.
- Full AST in Python — new dependency / maintenance cost.

## Go Version Semantics

**Decision**: Runners flag pre-1.22 loop capture patterns regardless of `go.mod`;
catalog notes Go 1.22 per-iteration variable fix.

**Rationale**: Production codebases (consensus clients, bridges) still ship pre-1.22
patterns per Sigma Prime.

## Bundle / Imports

**Decision**: `expand_local_imports` accepted as no-op (adapter contract R2).

**Rationale**: Multi-file Go module graph deferred; single-file analysis matches MVP
for other adapters' first landing.

## Task Numbering

**Decision**: Tasks **1-18** align with catalog `task_id`; meta **0** = run all.

**Rationale**: Consistent with Rust language tasks 9-23 and Solidity 1-15.
