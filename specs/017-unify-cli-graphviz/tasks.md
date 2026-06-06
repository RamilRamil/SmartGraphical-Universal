---
description: "Task list for feature 017 — Unify CLI graphviz and web renderers"
---

# Tasks: Unify CLI graphviz and web renderers

> **Status (2026-06-06): COMPLETE.** All 14 tasks done. `core/graph.py` rewritten
> to render the canonical `model_graph_to_dict(model)` projection (same nodes/
> edges as web cytoscape) via data-driven GROUP_STYLE/EDGE_STYLE; the old
> `func_X_Y`/`var_`/`obj_`/`sysfunc_` scheme is gone. New
> `tests/unit/test_graph_renderer_unified.py` proves node-id + edge parity for
> Solidity/C/Rust via a fake-graphviz recorder (no real graphviz needed) plus
> graceful-degradation and no-mutation tests. Full suite **498 passed** (493 + 5),
> 12 skipped (incl. the real-graphviz smoke, graphviz not installed here), 0
> failed. SC-002: web graph payload identical except the inherently variable
> `duration_ms` timing field (graph structure byte-identical). Found `workspace`
> as an extra canonical C node group during T003 and added it to GROUP_STYLE.

**Input**: Design documents from `specs/017-unify-cli-graphviz/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/renderer.md, quickstart.md

**Tests**: Targeted tests requested (Principle VII + FR-008): a CLI↔canonical
node-id parity test and a graceful-degradation test. The web graph payload is
pinned byte-for-byte by existing golden/contract tests + a snapshot oracle.

**Hard rules**: keep `GraphBuilder.render(model, output_label)` and
`AnalysisService.render_graph(context)` signatures unchanged (no caller edits).
Treat the canonical dict as read-only (don't mutate the web payload). Preserve
the graphviz-None graceful path.

**Paths** relative to `SmartGraphical/`. Python = `.venv/bin/python` (set
`PYTHONPATH=.` for ad-hoc scripts).

---

## Phase 1: Setup (baseline & oracle)

- [X] T001 Confirm baseline: `.venv/bin/python -m pytest -q` (expect 493 passed,
  11 skipped).
- [X] T002 Capture the web graph-payload baseline per `quickstart.md` §0 into
  `/tmp/graph_payload_baseline.json` (Solidity/C/Rust fixtures) — the SC-002
  oracle proving the web projection is untouched.
- [X] T003 Record the canonical vocabulary actually emitted for the fixtures:
  `PYTHONPATH=. .venv/bin/python -c "from smartgraphical.services.serializers import model_graph_to_dict; ..."` to list the node `group`s and edge `kind`s present, so GROUP_STYLE/EDGE_STYLE cover them (defaults handle the rest).

---

## Phase 2: Foundational (visual mapping tables)

- [X] T004 In `smartgraphical/core/graph.py`, add module-level `GROUP_STYLE`
  (canonical node `group` → graphviz node attrs), `EDGE_STYLE` (canonical edge
  `kind` → graphviz edge attrs), `DEFAULT_NODE_STYLE`, and `DEFAULT_EDGE_STYLE`,
  per `data-model.md`. Keep the existing color constants. Do not wire them yet.

**Checkpoint**: module still imports; suite still green.

---

## Phase 3: User Story 1 — One projection feeds both renderers (P1) 🎯 MVP

**Goal**: `GraphBuilder.render` draws from `model_graph_to_dict(model)`; CLI node
ids == canonical node ids.

**Independent test**: parity test green; web payload diff identical.

- [X] T005 [US1] Rewrite `GraphBuilder.render(model, output_label)` in
  `core/graph.py` to: call `from smartgraphical.services.serializers import
  model_graph_to_dict`; build `graph = model_graph_to_dict(model)`; create
  `cluster_*` subgraphs from `group in {type, tile}` nodes; emit nodes carrying a
  non-empty `parent` inside their parent cluster and parentless non-compound
  nodes at top level, each via `GROUP_STYLE.get(group, DEFAULT_NODE_STYLE)` using
  the canonical `id`/`label`; draw every edge `source -> target` via
  `EDGE_STYLE.get(kind, DEFAULT_EDGE_STYLE)` with the canonical `label`. Preserve
  the `graphviz is None` guard/message and the
  `dot.render(output_label + ".gv", directory="", view=False)` call.
- [X] T006 [US1] Remove the old parallel scheme from `core/graph.py`: the
  `func_<type>_<name>` / `var_` / `obj_` / `sysfunc_` node-id construction and the
  per-edge_kind walk over `model.types` / `model.call_edges`. Drop
  `sanitize_graph_token` if unused (keep only if still needed for cluster names).
- [X] T007 [US1] Factor the draw logic so it is testable without real graphviz:
  e.g. a pure helper `plan_render(model) -> (nodes, edges)` returning what will be
  drawn, or ensure `render` works against a fake `graphviz.Digraph` recording
  `node`/`edge`/`subgraph` calls. (Implementation detail; serves the parity test.)
- [X] T008 [US1] Add `tests/unit/test_graph_renderer_unified.py::parity`: for
  Solidity/C/Rust fixtures, assert the set of node ids `render` would draw equals
  `{n["id"] for n in model_graph_to_dict(model)["nodes"]}` and every canonical
  edge `(source,target)` is drawn. Use the fake-graphviz recorder or the pure
  helper (no real graphviz needed).
- [X] T009 [US1] Verify US1: web payload unchanged — re-run the snapshot
  (quickstart §2) and `diff` against `/tmp/graph_payload_baseline.json` →
  IDENTICAL; parity test green.

**Checkpoint**: CLI and web share one projection; node-id parity proven; web
payload identical. MVP delivered.

---

## Phase 4: User Story 2 — graphviz still works + graceful degradation (P2)

**Goal**: render path emits an artifact when graphviz is present and never crashes
when absent.

- [X] T010 [US2] Add `tests/unit/test_graph_renderer_unified.py::graceful`:
  set `core.graph.graphviz = None` (monkeypatch) and assert `GraphBuilder().render(model, label)`
  returns without raising and prints the not-installed message.
- [X] T011 [US2] Add a render smoke check that runs only when graphviz is
  importable (otherwise `skipTest`): call `render` on a fixture in a temp dir and
  assert it completes without error (artifact emitted). Also assert
  `model_graph_to_dict(model)` is equal before/after a `render` call (no
  projection mutation).

**Checkpoint**: optional-dependency contract preserved; no projection side effects.

---

## Phase 5: Polish & cross-cutting verification

- [X] T012 [P] SC-004 duplication check: `grep -nE 'func_\{|var_\{|sysfunc_|obj_\{' smartgraphical/core/graph.py`
  returns nothing.
- [X] T013 [P] SC-005 confirm graceful path via the test from T010.
- [X] T014 Final regression: `.venv/bin/python -m pytest -q` green (≥ 493 + new
  tests, 0 failed). Mark tasks [X] and add a status note to this file.

---

## Dependencies & ordering

- Setup (T001–T003) → first.
- Foundational (T004) → after Setup; before US1 wiring.
- US1 (T005–T009) → after T004. T005→T006→T007 are the same file, sequential;
  T008 after T007; T009 after T008.
- US2 (T010–T011) → after US1 (needs the new render in place).
- Polish (T012–T014) → after US2; T012/T013 are [P].

## Implementation strategy

- **MVP = US1**: the single-projection rewrite + parity proof is the whole value
  (Principle V). US2 preserves the optional-dependency contract; Polish confirms
  the duplication is gone and the suite is green.
