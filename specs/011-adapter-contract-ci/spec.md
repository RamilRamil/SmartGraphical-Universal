# Feature Specification: Adapter Contract, Restored C/Rust Web Analysis, and CI Gate

**Feature Branch**: `011-adapter-contract-ci`

**Created**: 2026-06-01

**Status**: Draft

**Input**: Foundation hardening — give all language adapters one enforced contract, restore C/Rust analysis through the web path, and add a CI gate so the regression class that is currently breaking the suite cannot recur.

## Context

SmartGraphical supports three target languages (Solidity, C/Solana, Rust/Stellar). Analysis is reached two ways: the CLI (single-file path) and the web/HTTP path (the `web_api` facade, used by the web UI). Today the web path is broken for two of the three languages, the suite is red, and nothing automatically catches it. This feature is foundation work that unblocks all later improvements; it changes no rules and no graph/findings UI.

This feature is governed by the project constitution (v1.0.0), specifically Principle III (one shared adapter contract), Principle VI (stable machine-readable contracts), and Principle VII (green suite is a release blocker; CI enforces it).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Analyze C and Rust through the web path (Priority: P1)

An auditor opens the web UI (or any caller of the web facade), uploads a C file or a Rust/Stellar file — as a single file or as a multi-file bundle — and receives a successful analysis and graph, exactly as they already do for Solidity. No crash occurs from a mismatch between how the facade calls an adapter and what that adapter accepts.

**Why this priority**: This is a user-facing outage. Right now any C or Rust analysis through the web path fails outright, so two of three advertised languages are unusable in the primary UI. Restoring it is the single highest-value fix.

**Independent Test**: Run the previously failing C and Rust web-facade and bundle tests and confirm they pass; manually upload `tests/fixtures/c/MinimalTu.c` and a Rust fixture through the web path and confirm findings + graph render without error.

**Acceptance Scenarios**:

1. **Given** a single C source file, **When** it is analyzed through the web path (single task and "all"), **Then** a result with findings and a graph payload is returned and no interface-mismatch error is raised.
2. **Given** a single Rust/Stellar source file, **When** it is analyzed through the web path, **Then** a result with findings and a graph payload is returned without error.
3. **Given** a multi-file C bundle and a multi-file Rust bundle, **When** each is analyzed through the web path, **Then** a combined result and graph are returned without error.
4. **Given** a Solidity file or bundle, **When** it is analyzed through the web path, **Then** the result is byte-for-byte equivalent to the current (pre-change) output.

---

### User Story 2 - One enforced adapter contract (Priority: P1)

A maintainer adds or modifies a language adapter and is prevented from silently diverging from the shared analysis interface. All adapters expose the same entry point (same call signature, same normalized return type), and an automated check fails the moment one does not.

**Why this priority**: The outage in US1 exists only because the three adapters drifted apart with nothing watching. Without an enforced contract the fix is temporary; with it the whole class of bug is closed. Equal priority to US1 because shipping the fix without the guard invites immediate regression.

**Independent Test**: A conformance test iterates every registered adapter and asserts each conforms to the shared interface; deliberately breaking one adapter's signature makes the test fail.

**Acceptance Scenarios**:

1. **Given** the set of registered language adapters, **When** the conformance check runs, **Then** every adapter is confirmed to expose the shared analysis entry point and to return the normalized model type.
2. **Given** an adapter whose entry point omits or renames a contract parameter, **When** the conformance check runs, **Then** the check fails and names the offending adapter.
3. **Given** the bundle local-import-expansion option, **When** it is passed to any adapter, **Then** the adapter accepts it; an adapter that does not implement local-import expansion treats it as a no-op instead of failing.

---

### User Story 3 - CI gate keeps the suite green (Priority: P2)

A contributor pushes a change or opens a pull request and an automated pipeline runs the full test suite plus a machine-readable CLI smoke, reporting a clear pass/fail that blocks merging on failure.

**Why this priority**: CI is what makes US1/US2 durable, but it depends on the suite first being green (US1+US2). High value, sequenced after the fixes.

**Independent Test**: Open a pull request with an intentionally failing test and confirm the pipeline reports failure; open one with a green tree and confirm it passes.

**Acceptance Scenarios**:

1. **Given** a push or pull request, **When** the pipeline runs, **Then** it executes the full test suite and a CLI run that emits machine-readable output, and reports success only if both succeed.
2. **Given** a change that breaks any test, **When** the pipeline runs, **Then** it reports failure as a blocking signal.

### Edge Cases

- **Multi-file bundles** for C and Rust must traverse the same facade path as single files without an interface mismatch.
- **Optional renderer absent**: when the optional graph image renderer (graphviz) is not installed, analysis still completes and the web graph payload is still produced (the image step degrades gracefully, per constitution Technology Constraints).
- **Future fourth adapter**: a new adapter that forgets the contract is caught by the conformance check rather than failing at runtime for an end user.
- **Unknown/oversized input** behavior is unchanged by this feature (existing validation still applies).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST analyze C and Rust/Stellar sources through the same web/HTTP entry path used for Solidity — for both single files and multi-file bundles — without raising any error attributable to an adapter interface mismatch.
- **FR-002**: All registered language adapters MUST expose an identical analysis entry interface: the same invocation signature and a return value of the normalized audit model type.
- **FR-003**: The system MUST provide an automated conformance check that fails, and identifies the offending adapter, if any registered adapter deviates from the shared interface.
- **FR-004**: The shared interface MUST accept the bundle local-import-expansion option uniformly across all languages; an adapter that does not implement local-import expansion MUST accept the option and treat it as a no-op rather than failing.
- **FR-005**: Solidity analysis behavior and output shape MUST remain unchanged; every currently passing Solidity test MUST continue to pass (backward compatibility).
- **FR-006**: An automated CI pipeline MUST run the full test suite and a machine-readable CLI smoke on every push and pull request and MUST surface failure as a blocking signal.
- **FR-007**: After this feature, the full test suite MUST pass with zero failures.
- **FR-008**: The solution MUST NOT introduce a new AST/grammar/parser dependency; it is contract alignment, not a parser rewrite (constitution Principle I).

### Key Entities

- **Adapter Contract**: the single shared interface every language adapter implements — one analysis entry point (fixed signature, including the uniformly-accepted local-import-expansion option) returning the normalized audit model.
- **Language Adapter**: the Solidity, C/Solana, and Rust/Stellar implementations that must conform to the Adapter Contract.
- **Conformance Check**: an automated test that verifies every registered adapter satisfies the Adapter Contract.
- **CI Pipeline**: the automated gate that runs the test suite and CLI smoke on push/PR and blocks on failure.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Analyzing a file through the web path succeeds (returns findings + graph, zero crashes) for all three languages — Solidity, C, and Rust/Stellar — in both single-file and bundle modes.
- **SC-002**: The full test suite reports zero failures (down from 17 failing today).
- **SC-003**: Introducing an adapter that violates the shared contract is caught automatically by the conformance check (verified by a deliberate break), with zero such mismatches reaching runtime.
- **SC-004**: Every push and pull request triggers the pipeline, and a tree with any failing test is reported as failing (blocking), with results available without manual local steps.
- **SC-005**: Solidity output is unchanged — 100% of previously passing Solidity tests still pass.

## Assumptions

- The local-import / bundle-expansion behavior remains Solidity-only in this feature; C and Rust accept the option as a no-op until they implement their own expansion later (out of scope here).
- The CI provider is GitHub Actions (the repository targets GitHub remotes via the Spec Kit git extension); the pipeline runs on a Python version matching the project minimum (3.10+).
- Existing fixtures under `tests/fixtures/` (C and Rust) are sufficient to exercise the restored web path; no new sample corpora are required.
- The 3 currently red tests that are not C/Rust facade failures (e.g., a Solidity snapshot and C graph-hint tests) are in scope for SC-002 "zero failures" and will be triaged as part of reaching a green suite.

## Non-Goals

- Implementing local-import / bundle-expansion semantics for C or Rust.
- Any dataflow analysis work (reserved for a later feature).
- Any change to findings content, rules, or the graph/findings UI.
- Refactoring the `web_api` module's bundle-stitching logic (reserved for the graph-maturity feature).
