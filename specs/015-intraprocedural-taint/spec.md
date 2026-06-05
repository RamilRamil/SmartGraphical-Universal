# Feature Specification: Pragmatic Intra-Procedural Taint / Dataflow Facts

**Feature Branch**: `015-intraprocedural-taint`

**Created**: 2026-06-02

**Status**: Draft

**Input**: A lightweight, heuristic intra-procedural taint pass that tracks untrusted input reaching sensitive sinks within a function, so the `requires_dataflow` rules that are registered-but-inert can finally run, and a portable "untrusted input reaches a sensitive sink unguarded" rule can fire — surfaced as hypotheses, never proofs.

## Context

Five of the C/Solana rules are marked `requires_dataflow: true` and are registered but **skipped** — they cannot fire because nothing computes input→sink flow. This feature adds a best-effort, intra-procedural taint pass over the **existing normalized facts** (function inputs, statements, mutations, calls, guards) and exposes additive `dataflow` facts that those rules — and a new portable rule — consume. It is deliberately heuristic (constitution Principle I): line/statement matching, single function at a time, no AST, no pointer analysis, accepting false positives and negatives. Findings are medium confidence at best and recorded as hypotheses for a human (Principle II).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Compute intra-procedural taint facts (Priority: P1)

For each function, the analyzer marks untrusted **sources** (parameters; network/packet/syscall reads) and **sinks** (state mutations; critical operations), propagates taint statement-by-statement, and records — as additive `dataflow` facts on the model — which sources reach which sinks and whether a guard intervened.

**Why this priority**: every dataflow rule depends on these facts; nothing fires without them. The facts are independently valuable as an exploration aid.

**Independent Test**: on a fixture where a parameter flows into a state write with no guard, the function's `dataflow` facts list that source→sink pair; on a guarded fixture, the pair is marked guarded.

**Acceptance Scenarios**:

1. **Given** a function where an input is assigned into a sink statement, **When** the taint pass runs, **Then** the `dataflow` facts include that source→sink reachability.
2. **Given** a `require`/`if` guard between the source and the sink, **When** the pass runs, **Then** the pair is recorded as guarded.
3. **Given** a function with no source-to-sink flow, **When** the pass runs, **Then** no taint pair is recorded (no false reachability).
4. **Given** the same input, **When** the pass runs twice, **Then** the facts are identical (deterministic).

---

### User Story 2 - Portable "tainted input reaches a sink unguarded" rule (Priority: P1)

A portable rule consumes the taint facts and emits a medium-confidence finding when an untrusted source reaches a sensitive sink with no intervening guard.

**Why this priority**: it is the first concrete payoff of the facts and the clearest demonstration that dataflow now works end-to-end. Pairs with US1 as the MVP.

**Acceptance Scenarios**:

1. **Given** a fixture with an unguarded tainted source→sink, **When** the rule runs, **Then** it emits a finding with evidence (the source and sink statements/lines) and medium confidence.
2. **Given** a guarded flow, **When** the rule runs, **Then** it does not fire.
3. **Given** a function with no flow, **When** the rule runs, **Then** it does not fire.

---

### User Story 3 - Graduate the `requires_dataflow` rules (Priority: P2)

The rules currently marked `requires_dataflow: true` execute against the new facts instead of being skipped, emitting medium/low-confidence findings. At least one is demonstrated end-to-end on a fixture; the rest become runnable rather than inert.

**Acceptance Scenarios**:

1. **Given** the dataflow facts are present, **When** analysis runs, **Then** the previously-skipped `requires_dataflow` rules are invoked (not skipped).
2. **Given** a fixture matching a graduated rule's pattern, **When** it runs, **Then** it emits a finding at the catalog-declared (medium/low) confidence.
3. **Given** a function with no relevant flow, **When** a graduated rule runs, **Then** it stays silent (no spurious finding).

---

### User Story 4 - Honest, hypothesis-level output (Priority: P2)

Taint findings are clearly heuristic: medium confidence at most, with evidence, and the trade-offs (false positives/negatives, intra-procedural only) are documented; nothing is presented as a proven dataflow result.

**Acceptance Scenarios**:

1. **Given** any dataflow finding, **When** it is shown, **Then** its confidence is at most "medium" and it carries source/sink evidence.
2. **Given** the heuristic's limits, **When** a maintainer reads `KNOWN_QUIRKS`, **Then** the intra-procedural / FP-FN trade-offs are recorded there.

---

### User Story 5 - Explain why a finding fired (Priority: P3)

Exploration output can list a function's tainted source→sink paths, so an auditor sees the basis for a dataflow finding.

**Acceptance Scenarios**:

1. **Given** a function with taint facts, **When** exploration output is produced, **Then** it lists the source→sink paths (source, sink, guarded flag).

### Edge Cases

- A source that is reassigned to a constant before the sink → taint cleared (not reported), best-effort.
- A sink reached only on a guarded path → reported as guarded, not as an unguarded finding.
- A function with no recognizable source or sink → no taint facts (silent), not an error.
- Aliasing / pointer indirection the heuristic cannot follow → a false negative (documented limit), never a crash.
- A taint pass over a huge function → bounded work; it must not hang or blow up.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The analyzer MUST compute, per function, intra-procedural taint from untrusted sources (inputs; network/packet/syscall reads) to sensitive sinks (state mutations; critical operations), using only the existing normalized facts and line/statement heuristics (no AST/pointer analysis).
- **FR-002**: Taint results MUST be exposed as **additive** `dataflow` facts on the model (source→sink pairs with a guarded flag), not changing any existing fact or contract.
- **FR-003**: The taint pass MUST record whether a guard intervenes between a source and a sink, and MUST NOT report a guarded flow as unguarded.
- **FR-004**: A portable rule MUST emit a medium-confidence finding when an untrusted source reaches a sensitive sink with no intervening guard, with source/sink evidence.
- **FR-005**: The rules marked `requires_dataflow: true` MUST be executed against the facts (no longer skipped); at least one MUST be demonstrated firing on a fixture, and all MUST be runnable without error.
- **FR-006**: Every dataflow finding MUST carry a confidence no higher than "medium" and MUST include evidence; nothing is presented as proven.
- **FR-007**: The taint pass MUST be deterministic and bounded (no hang/blowup on large functions).
- **FR-008**: The feature MUST NOT change existing (non-dataflow) findings, the graph, or output contracts for consumers that ignore the new facts.
- **FR-009**: The heuristic trade-offs (intra-procedural only, FP/FN, no aliasing) MUST be recorded in `KNOWN_QUIRKS.md`.

### Key Entities

- **Taint source**: an untrusted origin in a function (a parameter, or a network/packet/syscall read), identified heuristically.
- **Taint sink**: a sensitive destination (a state mutation or critical operation).
- **Dataflow fact**: per function, the set of source→sink reachability pairs, each with a `guarded` flag and the source/sink statements — additive on `findings_data.function_facts.dataflow`.
- **Dataflow finding** (existing Finding shape): emitted by the portable rule and the graduated rules; confidence ≤ medium; carries source/sink evidence.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On a fixture with an unguarded tainted source→sink, the taint facts record the pair and the portable rule emits exactly one medium-confidence finding; on a guarded fixture, neither fires.
- **SC-002**: All 5 `requires_dataflow` rules are invoked during analysis (0 silently skipped), and at least 1 fires on a matching fixture.
- **SC-003**: Taint facts are deterministic — identical across two runs on the same input.
- **SC-004**: No dataflow finding exceeds "medium" confidence.
- **SC-005**: Existing findings/graph/contract tests are unchanged (no regression) for code that ignores dataflow facts.
- **SC-006**: A maintainer can read, from exploration output, the source→sink path behind a dataflow finding.

## Assumptions

- C first (the `requires_dataflow` rules are C/Solana), with the portable rule applied where the normalized facts also support Solidity.
- "Untrusted source" and "sensitive sink" are heuristic sets seeded from the existing fact vocabulary (parameters, syscalls/packet reads; mutations/critical calls); they can be tuned later.
- Intra-procedural only — a source defined in another function is out of scope (documented false negatives).
- Medium confidence is the ceiling because the analysis is heuristic and not path-sound.

## Non-Goals

- Interprocedural / cross-function dataflow; pointer or alias analysis.
- Soundness or completeness; preprocessor/macro expansion.
- Languages beyond those whose adapters emit the needed facts (C first; portable where Solidity facts allow).
- A graph-UI visualization of taint paths (possible future feature).
- Changing rule confidence levels declared in the catalogs beyond honoring "medium ceiling".
