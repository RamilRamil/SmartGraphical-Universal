# Research: Decompose the web_api god-module

Phase 0 — no open `NEEDS CLARIFICATION` items. The spec is a behaviour-preserving
refactor with a fully enumerated public surface, so research is about *how* to
move code safely, not *what* to build.

## Decision 1 — Module vs package for `web_api`

**Decision**: Keep `web_api.py` as a single module that re-exports from new
sibling modules; do NOT convert it into a `web_api/` package.

**Rationale**: The import path `smartgraphical.services.web_api` must stay
identical for ~17 callers. A thin module re-exporting siblings achieves this with
the smallest diff and no package/`__init__` ambiguity. Converting to a package
risks `__pycache__` churn and subtle import-resolution differences for no benefit.

**Alternatives considered**:
- `web_api/` package with submodules — more "modern" but larger blast radius and
  no functional gain; rejected.
- Leave everything in place and only add section comments — does not satisfy
  SC-003/SC-004 (single responsibility, 70% size reduction); rejected.

## Decision 2 — Dependency direction & cycle avoidance

**Decision**: One-way dependency: `web_api` → `analyze_facade` →
{`bundle_graph`, `task_catalog`}. Leaf modules import only from adapters,
serializers, and `interfaces.cli.main`; never from `web_api` or each other.

**Rationale**: `web_api.py` today already imports CLI helpers
(`ALLOWED_MODES`, `_build_service`, `_resolve_language`) and serializers; those
imports move down with the facade/leaf code unchanged. Since nothing the new
modules import will import `web_api`, no cycle can form. `bundle_graph` and
`task_catalog` are independent of each other.

**Risk check — CONFIRMED**: `interfaces/cli/main.py` deliberately does NOT import
`web_api` (it carries a comment "cannot import web_api here: circular" and
duplicates `META_TASK_ALL_ID` to avoid the cycle). Therefore the new modules
importing `cli.main` (as `web_api` does today) stay acyclic. **Constraint**:
`cli.main` MUST keep its local `META_TASK_ALL_ID` duplication — do NOT make it
import the relocated constant from `task_catalog`, because `task_catalog` imports
`cli.main` and that would form a cycle. FR-007 (no caller edits) already enforces
leaving `cli.main` untouched, so this is satisfied for free.

## Decision 3 — How "byte-for-byte identical" is enforced

**Decision**: Capture a pre-refactor snapshot of `graph(...)` and
`analyze_all(...)` JSON for representative Solidity/C/Rust single-file and bundle
fixtures, then assert equality after the refactor. The existing golden/serializer
tests and the three task-coverage manifest tests provide the rest of the net.

**Rationale**: SC-002 demands byte-level equivalence; a captured snapshot is the
most direct proof and catches accidental reordering/whitespace drift introduced
by a careless move. The snapshot is a throwaway verification step (documented in
quickstart), not necessarily a committed fixture, since the standing golden tests
already pin most shapes.

**Alternatives considered**:
- Trust the existing suite alone — strong but does not explicitly cover every
  bundle permutation's full payload; the snapshot adds cheap certainty.

## Decision 4 — Move verbatim, do not "improve"

**Decision**: Relocate functions exactly as written (same names, same bodies,
same private underscores). No renaming, no signature changes, no logic tidy-ups
in this feature.

**Rationale**: Mixing a move with edits destroys the ability to reason "the diff
is a pure move" and defeats the no-behaviour-change guarantee. Any cleanup is a
separate future change. This also keeps `git diff` reviewable as relocation.

## Decision 5 — Re-export mechanism

**Decision**: `web_api.py` uses explicit `from .analyze_facade import (...)`,
`from .task_catalog import (...)`, `from .bundle_graph import (...)` plus an
`__all__` listing the public surface. The two externally-used private helpers
(`_solidity_file_import_paths`, `_rust_collect_module_links`) are imported by name
so `web_api._solidity_file_import_paths` keeps resolving.

**Rationale**: Explicit imports (not `import *`) make the preserved surface
auditable and let the new facade test assert each symbol. `__all__` documents the
intended public API without breaking the private-helper re-exports (which are
imported explicitly regardless of `__all__`).

## Open risks

- A helper currently relies on a module-level constant that lands in a different
  module (e.g., `BUNDLE_MANIFEST_BASENAME` used by both validation and bundle
  code). Mitigation: place each constant in the module that owns its dominant
  use and import it where also needed; verified by running the suite.
- Test files import private helpers (`_solidity_file_import_paths`,
  `_rust_collect_module_links`) — already enumerated; the facade test will fail
  loudly if any re-export is missed.
