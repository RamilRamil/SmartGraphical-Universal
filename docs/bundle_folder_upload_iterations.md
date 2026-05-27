# Plan: drag-and-drop folder (tree bundle) iterations

ASCII-only examples in this file where code/strings are shown.

This document splits the work for **folder-shaped uploads** (relative paths preserved) into concrete iterations. It aligns with the broader multi-file goals in `docs/multi_file_analysis_plan.md` (especially M2–M4 and security notes).

## Goals (cross-cutting)

- **Single artifact, many files:** one bundle id, one combined graph scan where supported.
- **Relative paths:** client sends POSIX-style relative paths; server normalizes and rejects escapes (`..`, absolute paths, `\0`, oversize paths).
- **Manifest versioning:** flat layout remains manifest `version` 1; tree layout uses `version` 2 with `"layout": "tree"`.
- **`source_file` on nodes:** matches manifest member `path` (basename-only for legacy flat bundles; full `rel` for tree bundles).

## Iteration 1 — Backend contract and persistence (done)

**Scope:** protocol, disk layout, analysis glue, tests (no UI requirement).

| Item | Detail |
|------|--------|
| History ingest | `ingest_bundle_upload(members, tree_mode=False)`: flat mode = basename + collision suffixes + manifest v1; tree mode = `_normalize_bundle_rel_path`, unique paths, `_safe_write_bundle_file`, manifest v2. |
| Limits | Per-file cap, file count cap, total bundle bytes cap, rel path length/segment caps. |
| HTTP | `POST /api/artifacts/bundle`: multipart `files`; optional form field `bundle_paths_json` (JSON array of strings, length = number of files). Omit field = legacy flat behavior. |
| web_api | `_bundle_member_abs_paths` returns `(abs_path, manifest_rel)`; analyze/graph use full `rel` as merge tag and `source_file`. |
| Cross-file edges | Solidity/C/Rust bundle attach helpers resolve imports/includes using manifest paths + relative resolution + unambiguous basename fallback. |
| Tests | Unit: tree ingest, rejection of `..`; integration HTTP: `bundle_paths_json`, OpenAPI mention (when FastAPI stack available). |

## Iteration 2 — Frontend upload (done)

**Scope:** `UploadPage` builds multipart requests that preserve folder structure.

| Item | Detail |
|------|--------|
| Folder selection | `webkitdirectory` on "Select folder" (combined mode); `File.webkitRelativePath`; dropping a single folder uses `webkitGetAsEntry` directory walk. |
| FormData | `bundle_paths_json` when every file has a tree path; same order as `files` (`frontend/src/api/client.ts`). |
| UX | Preview lists relative paths; bundle layout hint (tree vs flat); limits: file count, per-file size, combined bundle total 64 MiB; client rejects `..` and absolute-looking paths. |
| Fallback | Multi-file selection without paths: flat bundle (omit `bundle_paths_json`). |

### Related implementation

- `frontend/src/pages/UploadPage.tsx`
- `frontend/src/api/client.ts` — `uploadArtifactBundle(files, bundleRelativePaths?)`
- `frontend/src/api/hooks.ts` — `UploadBundleVariables`

## Iteration 2b — Subfolder include filter (done)

**Scope:** Combined upload can include only selected immediate subfolders under the inferred tree root (spec `009-bundle-subfolder-select`).

| Item | Detail |
|------|--------|
| Helpers | `frontend/src/lib/bundleFolderFilter.ts` — common root, sibling subfolder list, path filter. |
| UX | After folder pick, checkboxes for each immediate subfolder (default all on); preview counts staged vs filtered files. |
| Upload | Subset of staged files + `bundle_paths_json`; backend unchanged. |
| Limits | At least one subfolder required when the picker is shown. |

## Iteration 3 — Docs, contract, and hardening (done)

| Item | Detail |
|------|--------|
| Graph schema | `docs/graph_schema_logic.md` §2.6 (manifest v1/v2, `source_file`, bundle edges); C/Rust pointers in `graph_schema_logic_c.md` §8.1, `graph_schema_logic_rust.md` §5.5. |
| OpenAPI | `POST /api/artifacts/bundle`: `File`/`Form` descriptions for `files` and `bundle_paths_json`; handler docstring references `invalid_payload` / `unsupported_file`. |
| Optional: archive | Not implemented; still out of scope until product asks (zip slip, limits). |
| Pipeline / HTTP tests | `test_web_api_contract`: tree manifest graph `source_file` tags; `test_http_contract`: tree bundle graph + `bundle_paths_json` validation errors + OpenAPI payload contains `bundle_paths_json`. |

## Iteration 4 — Quality of cross-file edges (full plan / M5)

Maps to **M5** in `docs/multi_file_analysis_plan.md`. Iterations 1–2 established **tree layout** and **manifest paths**; merge attaches `source_file` to every node. Iteration 4 improves **how reliably** bundle-only cross-file edges are **synthesized** after merge (Solidity imports, C local includes, Rust `mod` / `use`).

This section is **out of scope** for closing iterations 1–3 but is the natural next program once folder uploads are in production use.

### 4.0 Baseline (implemented today)

Code lives in `smartgraphical/services/web_api.py`:

| Helper | Role |
|--------|------|
| `_bundle_members_rel_set` | All manifest `path` strings for the bundle. |
| `_resolve_solidity_provider_rel` | Try import string as manifest path, then resolve relative to consumer directory (`PurePosixPath`), then **unique** basename match among `.sol` members. |
| `_resolve_c_provider_rel` | Same pattern for `#include` targets that look like project `.c`/`.h`. |
| `_resolve_rust_mod_provider_rel` | File-module ``mod foo;``: directory is the consumer file's parent plus one segment per enclosing inline ``mod bar { ... }`` (``_rust_collect_file_module_declarations``), then ``.../foo.rs`` or ``.../foo/mod.rs``. Brace matching is string-unaware (limitation for exotic sources). |
| `_resolve_rust_crate_provider_rel` | `use crate::x::...`: unique `.rs` member whose file stem equals first segment. |
| `_attach_*_bundle_*_edges` | Scan manifest members, parse source text with regexes, add `bundle_import` / `tile_to_tile` edges. |

**Guarantee today:** edges are **best-effort**; no edge is better than a wrong edge when ambiguous resolution would lie.

### 4.1 Problems to solve

1. **Ambiguity:** Two members `a/Token.sol` and `b/Token.sol` — import `"./Token.sol"` from `a/Caller.sol` should resolve inside `a/`, but a flat basename match returns nothing or the wrong file if logic falls through incorrectly. Today: directory-join usually wins; duplicate basenames **without** a unique basename fallback still yield **no** synthetic edge.
2. **Solidity remappings / `@/` roots:** Imports like `import "@openzeppelin/contracts/...` or project aliases are not applied; only paths that normalize into manifest `path` strings work.
3. **Rust `super` vs `mod`:** `super::bar` and `mod bar` share a heuristic path in the current implementation; nested modules (`src/lib.rs` vs `src/foo.rs` vs `src/foo/mod.rs`) can diverge from real `rustc` layout.
4. **Rust `crate::` root:** `_resolve_rust_crate_provider_rel` picks a **unique** stem match anywhere in the bundle, which is wrong for large crates with duplicate logical names or when the real root is not inferable from filenames alone.
5. **C system vs project headers:** Angle-bracket includes that are not bundle members are already skipped; long term, optional **include path list** (from compile_commands or user hint) could map more quoted paths.
6. **Observability:** No structured note on graph payload when resolution is ambiguous or skipped (auditors cannot see "missing edge because 2 candidates").

### 4.2 Design principles

- **Correctness over recall:** Prefer missing `bundle_*` edge over attaching to the wrong TU/module.
- **Determinism:** Same bundle manifest + file contents -> same synthetic edges (stable order, stable disambiguation rules).
- **Bounded work:** CPU and memory caps per bundle; refuse deep resolution passes on huge trees.
- **Contract:** Document in `docs/graph_schema_logic.md` what is guaranteed vs heuristic for bundle edges (extend §2.6 and language-specific docs).

### 4.3 Workstreams

#### A. Solidity

| Step | Action |
|------|--------|
| A1 | **Golden tests:** fixtures with duplicate basenames in different folders + relative imports that must **not** cross folders incorrectly. |
| A2 | **Optional remapping layer:** parse leading `import` lines or a small optional manifest field `solidity_remappings: [{prefix, path}]` (product decision) applied before `_resolve_solidity_provider_rel`. |
| A3 | **Import path normalization:** handle trailing comments, multiple spaces, and common `import {X} from "path";` shapes if not already fully covered by `_solidity_file_import_paths`. |

#### B. C

| Step | Action |
|------|--------|
| B1 | **Duplicate basename tests:** two `unit.h` in different directories; `#include "sub/unit.h"` from a known consumer path. |
| B2 | **Optional include search path:** optional bundle manifest extension `c_include_prefixes: string[]` (POSIX prefixes tried after dirname join) — only with traversal-safety rules mirroring `_safe_write_bundle_file` style checks. |

#### C. Rust

| Step | Action |
|------|--------|
| C1 | **Split `super` from `mod`:** resolve `super::foo` using parent **module directory** inferred from file path (heuristic: parent of consumer file for sibling modules; document limits). |
| C2 | **Crate root heuristic:** detect `src/lib.rs` / `src/main.rs` / package root from manifest layout; restrict `crate::` resolution to subtree or score candidates instead of global unique stem. |
| C3 | **Inline `mod foo {` / `mod foo;` from non-root files:** broaden regex or lightweight parse only where safe. |

#### D. Cross-cutting

| Step | Action |
|------|--------|
| D1 | **`graph.exploration_hints`:** optional `bundle_edge_resolution: { "<reason_key>": <count>, ... }` — only keys with count `> 0` (e.g. per-skip counters such as `skipped_solidity_ambiguous_basename`). |
| D2 | **Telemetry in findings:** out of scope unless product wants rule-level warnings on unresolved imports. |

### 4.4 Phased delivery (suggested)

| Phase | Focus | Exit criteria |
|-------|--------|---------------|
| **4a** | Tests + ambiguity fixtures for Solidity/C/Rust | CI tests fail if regression on duplicate-basename or folder-relative imports. |
| **4b** | Solidity remappings (optional manifest) OR documented "not supported" matrix | Doc + tests or explicit code path rejected. |
| **4c** | Rust `super` / crate-root heuristic | Tests for nested `src/` layouts; no increase in false-positive `bundle_import` edges on existing fixtures. |
| **4d** | Hints JSON + doc updates | `graph_schema_logic.md` describes hints field; serializer stays JSON-safe. |

### 4.5 Risks

- **Compile truth:** Without a compiler front-end, resolution will never match `solc`/`rustc`/`clang` 100%; document margin of error for auditors.
- **Creep:** Remappings and include paths multiply edge cases — gate behind manifest version bump if schema changes.
- **Performance:** Re-parsing all members on each graph request is already O(n); avoid O(n^2) unless batching with indexes (basename -> list of rels, trie by path prefix).

### 4.6 Related implementation map

- Edge attachment: `web_api.py` — `_attach_solidity_bundle_import_edges`, `_attach_c_bundle_include_edges`, `_attach_rust_bundle_module_edges`.
- Contract tests: `tests/unit/test_web_api_contract.py` (bundle import/include/mod cases); extend with iteration-4 fixtures.
- HTTP E2E (optional): `tests/integration/test_http_contract.py` for scans over tree bundles with conflicting basenames.

### 4.7 Non-goals for iteration 4

- Full compiler toolchain integration (solc `--standard-json`, `cargo`, compile_commands.json ingestion) unless later promoted from "optional".
- Zip / archive upload (remains separate decision; see iteration 3).

### 4.8 Implementation status (repository)

Delivered incrementally in code (see `smartgraphical/services/web_api.py`):

- **A1 / B1:** Golden-style unit tests in `tests/unit/test_web_api_contract.py` (`WebApiBundleIteration4Tests`): duplicate Solidity basename + relative import, ambiguous unqualified import, duplicate `unit.h` with `#include "sub/unit.h"`.
- **A2:** Optional manifest field `solidity_remappings` (pairs or `{prefix, path}` dicts); applied before `_resolve_solidity_provider_rel`.
- **C1:** `super::` uses parent directory first, then grandparent (`_resolve_rust_super_provider_rel`).
- **C2:** `crate::` resolution scopes to members under one inferred root when `lib.rs` / `main.rs` unambiguously contains the consumer (`_rust_pick_crate_root_for_consumer`, `_resolve_rust_crate_provider_rel`).
- **C3:** File-module ``mod name;`` inside inline ``mod outer { ... }`` resolves under ``parent/outer/name.rs`` (recursive scan + prefix stack; naive brace matching).
- **B2:** Optional manifest field `c_include_prefixes` for C bundles; quoted includes try `prefix/include_relpath` after consumer-relative join (`_resolve_c_provider_rel`).
- **D1:** After bundle edge attachment, non-zero skip counts are merged into `graph.exploration_hints.bundle_edge_resolution` (`_apply_bundle_edge_hints`).
- **A3:** Solidity import extraction: strip block comments first; then quote-aware removal of line `//` tails (paths with `//` inside quotes remain intact); braced `import { ... } from "path";` including multiline forms (`_solidity_file_import_paths`).

**Iteration 4 §4.3 status:** delivered in code with documented heuristics; remaining gaps are mostly compiler-faithfulness (e.g. Rust modules inside functions, `#[path]` modules) rather than missing scaffolding.

## Plan closure (iterations 1–3)

Deliverables for **folder-shaped bundle uploads** are complete when 1–3 are done:

1. Backend: ingest, manifest v1/v2, `/api/artifacts/bundle` + `bundle_paths_json`, `web_api` merge and `source_file`, tests.
2. Frontend: `UploadPage` folder + paths in `FormData`.
3. Docs: graph schema §2.6, C/Rust bundle notes, OpenAPI field descriptions, extra HTTP and `web_api` tests.

**Zip upload** remains explicitly out of scope until requested (see iteration 3 table).

## Mapping to M-milestones

| Milestone in `multi_file_analysis_plan.md` | These iterations |
|-------------------------------------------|----------------|
| M2 API bundle | Iteration 1 (HTTP + ingest), Iteration 2 (client) |
| M4 UI multi-upload | Iteration 2 |
| M5 stronger edges | Iteration 4 (full plan above) |

## Related files

- `docs/multi_file_analysis_plan.md` — multi-file goals and M0–M5.
- `docs/graph_schema_logic.md` — graph JSON and merge semantics.
- `smartgraphical/services/history_service.py` — ingest, manifest, path rules.
- `smartgraphical/interfaces/http/routes.py` — bundle upload route.
- `smartgraphical/services/web_api.py` — merge, `source_file`, bundle edges (iteration 4 focuses on `_resolve_*` and `_attach_*_bundle_*`).
- `frontend/src/pages/UploadPage.tsx` — folder / file upload UI.
- `frontend/src/api/client.ts` — bundle multipart client.
