# Implementation Plan: Adapter Contract, Restored C/Rust Web Analysis, and CI Gate

**Branch**: `011-adapter-contract-ci` | **Date**: 2026-06-01 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/011-adapter-contract-ci/spec.md`

## Summary

Restore web-path analysis for C and Rust/Stellar, formalize a single adapter
contract so the three adapters cannot silently diverge again, fix the two
non-facade graph/snapshot regressions that keep the suite red, and add a CI gate.

Root cause (confirmed by reading the code): `AnalysisService.analyze` forwards
`**parse_kwargs` straight to `adapter.parse_source`
(`smartgraphical/services/analysis_service.py:13`), and the web facade always
passes `expand_local_imports=...` (`smartgraphical/services/web_api.py:1251`).
Only `SolidityAdapterV0.parse_source(self, source_path, *, expand_local_imports=True)`
accepts it; `CBaseAdapterV0.parse_source(self, source_path)` and
`RustStellarAdapterV0.parse_source(self, source_path)` do not, so the facade
raises `TypeError` for C and Rust (14 of 17 failing tests). The CLI path
(`service.analyze(source_path)` with no kwarg) is unaffected.

Technical approach: introduce a shared adapter interface that all three adapters
implement with one `parse_source(source_path, *, expand_local_imports=True) ->
AnalysisContext` signature; C and Rust accept the flag as a documented no-op. Add
a conformance test over the registered adapters. Separately fix the stale
Solidity golden snapshot and the C include-template anchor-to-tile resolution.
Wire a GitHub Actions workflow running the suite plus a `sg_cli.py --format json`
smoke.

## Technical Context

**Language/Version**: Python 3.10+ (backend only; no frontend change in this feature).

**Primary Dependencies**: standard library only for the contract (`typing.Protocol`
or `abc` + `inspect`); existing `unittest`/`pytest` for the conformance test;
GitHub Actions for CI. No new runtime dependency (constitution Principle I).

**Storage**: N/A — no persistence or schema change.

**Testing**: existing `unittest`-style suite run via `pytest` (`.venv/bin/python -m
pytest`). New conformance test under `tests/unit/`.

**Target Platform**: Linux/macOS developer machines; CI on GitHub Actions
(ubuntu-latest, Python 3.12 to match the Docker image, with 3.10 as the floor).

**Project Type**: Python web service + CLI (single backend package
`smartgraphical/`, plus a separate React frontend that this feature does not touch).

**Performance Goals**: N/A — CI wall-clock should stay within a few minutes
(current suite runs in ~7-12s locally).

**Constraints**: Solidity behavior and output shape MUST be byte-for-byte
unchanged (FR-005, Principle VI); `web_api` facade stays pure/JSON-safe; no new
AST/grammar dependency (FR-008, Principle I).

**Scale/Scope**: 3 adapters; 1 new contract module; 1 serializer fix; 1 golden
snapshot update; 1 conformance test; 1 CI workflow; doc updates. ~17 red tests → 0.

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after design.*

| Principle | Assessment |
|-----------|------------|
| I. Pragmatic Parsing Over Full AST | PASS — contract alignment only; FR-008 forbids a new AST dependency. |
| II. Auditor-Centric, Human-in-the-Loop | PASS — no findings/evidence/confidence change; output semantics preserved. |
| III. Normalized Model Is the Contract | DIRECTLY SERVES — this feature creates the single enforced adapter contract the principle requires. |
| IV. Portability Across Languages | DIRECTLY SERVES — one `parse_source` contract across Solidity/C/Rust; conformance test guards it. |
| V. Two Pillars Stay Connected | PASS — the C include-template anchor fix restores correct graph node identity (anchor → `tile:` TU node), keeping graph and model entity identity aligned. |
| VI. Stable, Machine-Readable Contracts | PASS — Solidity output unchanged (FR-005); facade stays pure; CI smoke consumes `--format json`. |
| VII. Test & Traceability Gates | DIRECTLY SERVES — conformance test + green suite + CI gate; any newly surfaced quirk recorded in `KNOWN_QUIRKS.md`. |

**Result**: No violations. Complexity Tracking is empty.

## Project Structure

### Documentation (this feature)

```text
specs/011-adapter-contract-ci/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 — decisions
├── data-model.md        # Phase 1 — adapter contract shape
├── contracts/
│   ├── adapter-contract.md   # the parse_source interface every adapter implements
│   └── ci-workflow.md        # CI trigger + steps + pass/fail contract
├── quickstart.md        # how to validate this feature
└── checklists/
    └── requirements.md  # spec quality checklist (all passed)
```

### Source Code (repository root = `SmartGraphical/`)

```text
smartgraphical/
├── adapters/
│   ├── base.py                     # NEW: AnalysisAdapter Protocol + AnalysisContext return contract
│   ├── solidity/adapter.py         # already conforms (reference signature); no behavior change
│   ├── c_base/adapter.py           # CHANGE: parse_source(..., *, expand_local_imports=True) no-op
│   └── rust_stellar/adapter.py     # CHANGE: parse_source(..., *, expand_local_imports=True) no-op
└── services/
    └── serializers.py              # FIX: anchor → tile resolution in resolve_endpoint (model_graph_to_dict)

tests/
├── unit/
│   ├── test_adapter_contract_conformance.py   # NEW: every registered adapter conforms
│   └── test_c_adapter_model_graph.py          # passes once serializer fix lands
└── integration/
    └── test_solidity_adapter_fixtures.py      # UPDATE: refresh stale golden (amount now a state entity)

.github/
└── workflows/
    └── ci.yml                       # NEW: pytest + sg_cli.py --format json smoke on push/PR

docs/ , README.md                    # UPDATE: three languages (not two); note CI gate
```

**Structure Decision**: Single backend package. The shared contract lives at
`smartgraphical/adapters/base.py` (the adapter layer owns the adapter contract);
it references `AnalysisContext` from `smartgraphical/core/model.py`. No frontend
files are touched.

## Phase Overview

- **Phase 0 (research.md)**: resolve the contract return type question
  (`AnalysisContext` vs `NormalizedAuditModel`), the `expand_local_imports`
  uniformity strategy, Protocol vs ABC, and triage of the 3 non-facade failures.
- **Phase 1 (data-model.md + contracts/ + quickstart.md)**: define the adapter
  contract shape, the conformance check, and the CI workflow contract; write the
  validation quickstart; update the agent context file.
- **Phase 2 (/speckit.tasks)**: dependency-ordered tasks per user story.

## Complexity Tracking

No constitution violations — no entries.
