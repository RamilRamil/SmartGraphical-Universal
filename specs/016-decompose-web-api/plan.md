# Implementation Plan: Decompose the web_api god-module

**Branch**: `016-decompose-web-api` | **Date**: 2026-06-06 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/016-decompose-web-api/spec.md`

## Summary

Split `smartgraphical/services/web_api.py` (~1485 lines) into three focused
sibling modules under `smartgraphical/services/` — a bundle-graph assembly
module, a task-catalog module, and an analyze facade — while `web_api.py` becomes
a thin re-export facade that preserves every public symbol and every
externally-imported private helper. This is a behaviour-preserving structural
refactor; the existing 486-passing suite plus golden/serializer/contract tests
and byte-level graph snapshots are the safety net.

## Technical Context

**Language/Version**: Python 3.10+ (uses `X | None` syntax)

**Primary Dependencies**: standard library only for the moved code (`re`, `os`,
`json`, `hashlib`, `pathlib.PurePosixPath`); existing internal deps —
`adapters.*` registries, `services.serializers`, `services.analysis_service`,
`interfaces.cli.main` (`ALLOWED_MODES`, `_build_service`, `_resolve_language`).

**Storage**: N/A for this feature (history wiring is untouched).

**Testing**: pytest (unit + integration + contract + golden + serializer +
task-coverage manifests). No new framework.

**Target Platform**: Linux/macOS server-side Python; consumed by FastAPI routes,
the CLI, and the benchmark CLI.

**Project Type**: Single backend package (`smartgraphical/`) with a separate
frontend (untouched here).

**Performance Goals**: No change. Refactor must not add measurable overhead
beyond one extra module-import indirection.

**Constraints**: Zero observable behaviour change — identical function
signatures, JSON shapes, graph payloads, and error identities (Principle VI). No
import-statement changes in any caller outside the new modules and `web_api.py`.

**Scale/Scope**: One ~1485-line module → ~4 modules. ~17 caller files must
remain untouched.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Pragmatic Parsing Over Full AST** — ✅ No parsing change; heuristic code is
  moved verbatim, not rewritten. No new AST/grammar dependency.
- **II. Auditor-Centric** — ✅ Findings/evidence untouched; no output semantics
  change.
- **III. Normalized Model Is the Contract** — ✅ The normalized model and adapter
  contract are not touched; only the facade/assembly layering is reorganized.
- **IV. Portability** — ✅ No rule portability labels change. Solidity/C/Rust
  bundle logic stays equivalent, just relocated together.
- **V. Two Pillars Stay Connected** — ✅ Graph payloads are pinned byte-for-byte;
  finding↔node identity is unaffected.
- **VI. Stable, Machine-Readable Contracts** — ✅ **Central to this feature.**
  `web_api.*` facade functions stay pure and JSON-safe; output shape is preserved
  and guarded by existing contract tests plus a new facade re-export test. This
  refactor strengthens VI by making the "thin HTTP wrapper / shared facade" rule
  structurally obvious.
- **VII. Test & Traceability Gates** — ✅ Full suite must stay green; a targeted
  test locks the re-export contract. No new heuristic trade-off, so no
  `KNOWN_QUIRKS.md` entry is required (the move is behaviour-preserving).

**Result**: PASS. No violations; Complexity Tracking not required.

**Post-design re-check**: PASS (see end of Phase 1 — design introduces no new
public surface and no new dependency).

## Project Structure

### Documentation (this feature)

```text
specs/016-decompose-web-api/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output (module/responsibility map)
├── quickstart.md        # Phase 1 output (verification recipe)
├── contracts/
│   └── facade.md        # Phase 1 output (preserved public surface)
└── checklists/
    └── requirements.md  # from /speckit.specify
```

### Source Code (repository root)

```text
smartgraphical/services/
├── web_api.py            # BECOMES thin facade: re-exports public + 2 private helpers
├── bundle_graph.py       # NEW: multi-file bundle graph assembly (Sol/C/Rust)
├── task_catalog.py       # NEW: list_tasks, is_run_all_task, META_TASK_ALL_ID
├── analyze_facade.py     # NEW: analyze/analyze_all/graph/health + validation +
│                         #      WebApiError + ERROR_* sentinels
├── analysis_service.py   # unchanged
├── history_service.py    # unchanged
└── serializers.py        # unchanged

tests/unit/
└── test_web_api_facade_reexports.py   # NEW: locks the re-export contract
```

> **Implementation update (2026-06-06)**: the decomposition landed as **four**
> new modules, not three. During extraction a cycle surfaced
> (`task_catalog.list_tasks` ↔ the error/service helpers it shares with
> `analyze_facade`), so the stable error contract (`WebApiError`, `ERROR_*`) plus
> the safe service/language wrappers (`_resolve_language_safe`,
> `_build_service_safe`) were extracted into a foundational `web_support.py` that
> imports only `cli.main`. Final acyclic layering:
> `web_api → analyze_facade → {bundle_graph, task_catalog} → web_support`.

**Structure Decision**: Keep `web_api.py` as a *module* (not a package) that
re-exports from the new sibling modules. This preserves the import path
`smartgraphical.services.web_api` byte-for-byte and avoids touching
`__pycache__`/package layout. The dependency direction is strictly one-way:
`web_api` → `analyze_facade` → {`bundle_graph`, `task_catalog`}; both leaf
modules depend only on adapters/serializers/cli (never back on web_api), so no
import cycle is possible.

## Module boundary map (target)

| New module | Owns (current web_api.py regions) | External re-export obligation |
|------------|-----------------------------------|-------------------------------|
| `bundle_graph.py` | bundle regex constants (`_RE_*`), `_touch_bundle_stat`, all `_solidity_*`/`_c_*`/`_rust_*` resolvers, `_attach_*` edge builders, `_consolidate_solidity_bundle_graph`, `_revalidate_bundle_graph`, `_apply_*`, supporting helpers (≈ lines 46–1191) | `_solidity_file_import_paths`, `_rust_collect_module_links` (imported by other modules/tests) |
| `task_catalog.py` | `META_TASK_ALL_ID`, `is_run_all_task`, `list_tasks` | `is_run_all_task`, `list_tasks` |
| `analyze_facade.py` | `ERROR_*` constants, `WebApiError`, all `_validate_*`/`_resolve_*_safe`/`_build_service_safe`/`_analyze_source`/`_base_report`/`_bundle_member_abs_paths`/`_analysis_source_steps`/`_is_bundle_root`/`_assert_consistent_bundle_language`, `health`, `analyze`, `analyze_all`, `graph` | `WebApiError`, `ERROR_INVALID_LANGUAGE` (+ other `ERROR_*`), `health`, `analyze`, `analyze_all`, `graph` |
| `web_api.py` (facade) | nothing of its own | every symbol above, via explicit imports + `__all__` |

## Complexity Tracking

> No Constitution Check violations. Section intentionally empty.
