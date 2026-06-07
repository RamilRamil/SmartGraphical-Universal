# Implementation Plan: Labeled Benchmark Corpus + Precision/Recall Runner

**Branch**: `014-rule-benchmark-corpus` | **Date**: 2026-06-02 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/014-rule-benchmark-corpus/spec.md`

## Summary

A measurement layer over the existing analyzer: human-authored label files declare,
per example contract, the **expected real** findings and the **known false
positives**; a deterministic runner analyzes each example, matches emitted
findings to labels, and reports recall + precision per rule and overall; a guard
test fails if recall drops below a recorded baseline. No rule/parser change.

Grounding (from the code):
- `web_api.analyze_all(path, language)` returns `report["findings"]` — a list of
  finding dicts (`rule_id`, `category`, `confidence`, `message`, `evidences[]`
  with `type_name`/`function_name`). This is the deterministic, in-process entry
  the runner uses (no subprocess; same facade used everywhere).
- The shared finding identity is `history_service._finding_key`
  `(rule_id, type_name, function_name, source_statement|statement, message)`.
- Checked-in synthetic fixtures under `tests/fixtures/solidity/` (MinimalGuard,
  ImportModifierFixture, MultiStateFields, cross_type pair, benchmark label seeds);
  local untracked contracts are not in git and are not measured by default.

## Technical Context

**Language/Version**: Python 3.10+ (measurement tooling + tests). No frontend.

**Primary Dependencies**: existing only — `web_api.analyze_all`, stdlib `json`.
No new dependency.

**Storage**: versioned label files + a recall baseline file, in the repo
(`tests/benchmark/`). No database.

**Testing**: pytest — unit tests of the metric logic on synthetic findings, plus
a corpus recall-regression guard.

**Target Platform**: developer / CI (runs headless).

**Project Type**: backend measurement tooling + test infrastructure.

**Performance Goals**: the full corpus (a handful of examples) runs in seconds;
determinism over speed.

**Constraints**: must not change analyzer output; reuse the shared finding
identity fields (no separate scheme); deterministic; labels are human-authored.

**Scale/Scope**: a curated corpus (>=3 labeled examples to start), one pure
metrics module, label files, a baseline, a runner CLI, and the guard/unit tests.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after design.*

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing Over Full AST | PASS — no parsing; measurement over emitted findings. |
| II. Auditor-Centric, Human-in-the-Loop | DIRECTLY SERVES — labels are human ground truth; the tool measures against them, it never self-grades or auto-labels. |
| III. Normalized Model Is the Contract | PASS — reads findings via the facade; no adapter/model change. |
| IV. Portability Across Languages | PASS — label format is language-neutral; Solidity first (that is what `local untracked contracts (not in git); checked-in fixtures live under tests/fixtures/solidity/` holds). |
| V. Two Pillars Stay Connected | N/A (rules pillar measurement); no graph change. |
| VI. Stable, Machine-Readable Contracts | DIRECTLY SERVES — consumes the stable JSON findings + shared identity; labels/baseline are additive versioned files; analyzer output unchanged. |
| VII. Test & Traceability Gates | DIRECTLY SERVES — the benchmark is reproducible test/traceability infra with a recall-regression guard. |

**Result**: No violations. Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/014-rule-benchmark-corpus/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 decisions
├── data-model.md        # label + result shapes, match key
├── contracts/
│   └── benchmark.md      # label-file format, runner CLI, metrics contract
├── quickstart.md
└── checklists/requirements.md  # all passed
```

### Source Code (repository root = `SmartGraphical/`)

```text
smartgraphical/benchmark/
├── __init__.py
└── corpus.py                 # NEW: pure logic — match key, load labels, evaluate metrics

tests/benchmark/
├── labels/
│   ├── GuardedWithdrawFixture.sol.json    # NEW: expected + false_positive labels (>=3 examples)
│   ├── StakingPoolFixture.sol.json
│   └── TokenRedeemFixture.sol.json
├── baseline.json                 # NEW: per-example recall baseline (recorded)
└── test_benchmark.py             # NEW: unit metrics tests + corpus recall guard

sg_benchmark.py                   # NEW: thin CLI — analyze labeled examples, print text + JSON report
```

**Structure Decision**: a pure `corpus.py` (deterministic functions: `match_key`,
`load_labels`, `evaluate`) so metrics are unit-testable in isolation; the CLI and
the guard test are thin consumers. Labels and baseline are versioned data under
`tests/benchmark/`. Analyzer access is the existing `web_api.analyze_all` facade.

## Phase Overview

- **Phase 0 (research.md)**: the benchmark match key (location projection of the
  shared identity), label format, how findings are obtained, precision/recall
  definitions, baseline strategy, determinism.
- **Phase 1 (data-model.md + contracts/ + quickstart.md)**: label/result entities,
  the label-file + CLI + metrics contracts, validation steps; update agent context.
- **Phase 2 (/speckit.tasks)**: tasks per user story (label authoring, metrics,
  recall guard, report), pure-module-first.

## Complexity Tracking

No constitution violations — no entries.
