# Implementation Plan: Pragmatic Intra-Procedural Taint / Dataflow Facts

**Branch**: `015-intraprocedural-taint` | **Date**: 2026-06-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/015-intraprocedural-taint/spec.md`

## Summary

Add a portable, heuristic intra-procedural taint pass over the normalized model
that records untrusted source -> sensitive sink reachability (with a guarded
flag) as additive per-function facts, then a portable rule that flags an
unguarded tainted flow at medium confidence.

**Discovery that reshapes scope (from reading the code)**: the five
`requires_dataflow` C rules are NOT skipped — they are registered (C tasks in
`c_base/adapter.py`) and executed, consuming bespoke facts the adapter already
builds in `_extract_dataflow_facts` (`program_guard_sites`, `return_error_codes`,
`io_uring_submit_sites`, `tile_markers`). So the docs' "registered but not
executed" is stale. The real gap is that there is **no generic, portable
source->sink taint** and **no portable taint rule**. Therefore:

- US1/US2 (generic taint facts + a portable rule) are the headline new capability.
- US3 is reframed honestly: confirm (with a test) that the 5 `requires_dataflow`
  rules are actually invoked (not skipped), and that the new taint facts are
  purely additive (no regression). One of them is demonstrated firing on a
  fixture. We do not pretend to "un-skip" rules that already run.

## Technical Context

**Language/Version**: Python 3.10+ (analysis core). No frontend.

**Primary Dependencies**: existing only — the normalized model + rule engine.
stdlib (`re`). No new dependency, no AST/parser (Principle I).

**Storage**: N/A (in-memory facts on the model).

**Testing**: pytest — unit on the taint pass (source->sink reachability + guard
detection on synthetic functions), the portable rule on fixtures, an invocation
test that the 5 `requires_dataflow` rules run, and a regression check.

**Target Platform**: developer / CI (headless).

**Project Type**: analysis-core feature (single backend package).

**Performance Goals**: bounded per-function work (linear in statements); the full
suite stays within current runtime.

**Constraints**: line/statement heuristics only (no AST/pointer analysis);
additive facts (`taint_paths`); medium-confidence ceiling; deterministic;
existing findings/graph/contracts unchanged for consumers that ignore the facts.

**Scale/Scope**: one core taint module, one additive model field, one wiring
point, one portable rule (registered in both language registries), fixtures +
tests, a KNOWN_QUIRKS entry.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after design.*

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing Over Full AST | PASS — statement/regex heuristics over existing normalized facts; FR-001 forbids AST/pointer analysis. |
| II. Auditor-Centric, Human-in-the-Loop | DIRECTLY SERVES — taint findings are medium-confidence hypotheses with source/sink evidence; never proofs (FR-006). |
| III. Normalized Model Is the Contract | DIRECTLY SERVES — taint is computed over `NormalizedFunction` facts and exposed as additive model facts; rules consume the model. |
| IV. Portability Across Languages | DIRECTLY SERVES — the pass is a core, language-agnostic step over the normalized facts; the portable rule runs on C and Solidity. |
| V. Two Pillars Stay Connected | PASS — no graph change (taint graph viz is a noted future); findings keep entity identity. |
| VI. Stable, Machine-Readable Contracts | PASS — `taint_paths` is an additive field; existing outputs unchanged (SC-005). |
| VII. Test & Traceability Gates | DIRECTLY SERVES — targeted tests for the pass/rule/invocation; KNOWN_QUIRKS records the heuristic limits (FR-009). |

**Result**: No violations. Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/015-intraprocedural-taint/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 decisions (incl. the "already executed" discovery)
├── data-model.md        # TaintPath + taint_paths field + source/sink vocabulary
├── contracts/
│   └── taint.md          # taint pass API, taint_paths shape, portable rule contract
├── quickstart.md
└── checklists/requirements.md  # all passed
```

### Source Code (repository root = `SmartGraphical/`)

```text
smartgraphical/
├── core/
│   ├── model.py                       # ADD: NormalizedFunction.taint_paths (additive field, default [])
│   ├── dataflow/
│   │   ├── __init__.py                 # NEW
│   │   └── taint.py                    # NEW: compute_taint(function) + apply_taint(model); pure, deterministic
│   └── rules/portable/
│       ├── __init__.py                 # NEW
│       └── tainted_input_unguarded_sink.py   # NEW: portable rule over taint_paths (confidence=medium)
└── services/
    └── analysis_service.py            # CHANGE: apply_taint(context.normalized_model) after parse (one seam, all languages)

smartgraphical/adapters/
├── solidity/adapter.py                # CHANGE: register the portable taint rule (new task id)
└── c_base/adapter.py                  # CHANGE: register the portable taint rule (new task id)

tests/
├── unit/test_taint_pass.py            # NEW: source->sink reachability + guard + determinism (synthetic)
├── unit/test_tainted_input_rule.py    # NEW: portable rule fires unguarded / silent guarded
└── unit/test_requires_dataflow_invoked.py  # NEW: the 5 requires_dataflow rules are invoked (US3)

tests/fixtures/{c,solidity}/           # ADD: a tainted-flow fixture (unguarded + guarded)
KNOWN_QUIRKS.md                        # ADD: intra-procedural / FP-FN / no-aliasing entry
```

**Structure Decision**: a **core, language-agnostic** taint pass (not per-adapter)
attaching an additive `taint_paths` field to each `NormalizedFunction`, applied
once in `AnalysisService.analyze` after parse. The portable rule reads
`function.taint_paths` and is registered in both language registries. The
existing C `dataflow` facts and rules are untouched (additive).

## Phase Overview

- **Phase 0 (research.md)**: the "already executed" discovery + US3 reframe;
  taint sources/sinks vocabulary; propagation + guard heuristics; where to wire
  the pass; the additive field vs the C `dataflow` slot; determinism.
- **Phase 1 (data-model.md + contracts/ + quickstart.md)**: TaintPath shape, the
  `taint_paths` field, the taint pass + portable rule contracts, validation;
  update agent context.
- **Phase 2 (/speckit.tasks)**: tasks per user story, pass-first.

## Complexity Tracking

No constitution violations — no entries.
