# Implementation Plan: Unify CLI graphviz and web renderers

**Branch**: `017-unify-cli-graphviz` | **Date**: 2026-06-06 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/017-unify-cli-graphviz/spec.md`

## Summary

Rewrite `core/graph.py::GraphBuilder.render` so it renders the PNG from the
**canonical** graph projection `serializers.model_graph_to_dict(model)` — the same
nodes/edges the web cytoscape view uses — instead of re-deriving a parallel graph
with its own `func_X_Y` node-id scheme. The graph structure then lives in exactly
one place; graphviz becomes a thin "draw this canonical dict to PNG" step with a
data-driven group→shape / kind→style mapping. graphviz stays optional and
degrades gracefully. The web JSON payload is unchanged.

## Technical Context

**Language/Version**: Python 3.10+

**Primary Dependencies**: `graphviz` (optional, already present);
`serializers.model_graph_to_dict` (canonical projection, already used by web).

**Storage**: N/A.

**Testing**: pytest. New: a CLI↔canonical node-id parity test and a
graceful-degradation test (graphviz absent). graphviz availability in CI is not
assumed — tests needing real rendering skip when graphviz is missing; the parity
test works on the dict, not the PNG.

**Target Platform**: CLI (PNG artifact) + the shared service layer.

**Project Type**: Single backend package; frontend untouched.

**Performance Goals**: No regression; one canonical projection call per render.

**Constraints**: Web graph payload (`model_graph_to_dict` / `model_summary_to_dict`)
byte-for-byte unchanged (FR-005). No findings/rule-output change (FR-006).
graphviz absence never crashes (FR-004). No caller-signature change
(`GraphBuilder.render(model, output_label)` and `service.render_graph(context)`
stay identical).

**Scale/Scope**: One module rewrite (`core/graph.py`, ~121 lines) + 1-2 tests.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Pragmatic Parsing Over Full AST** — ✅ No parsing change; renders an
  existing projection. No new heavyweight dependency (graphviz already optional).
- **II. Auditor-Centric** — ✅ External/unresolved nodes from the canonical
  projection now also appear in the CLI graph (boundary signals not hidden).
- **III. Normalized Model Is the Contract** — ✅ Both renderers consume the
  normalized-model-derived projection; nothing re-parses raw text.
- **IV. Portability** — ✅ One projection already handles Solidity/C/Rust; the CLI
  stops carrying its own per-shape logic.
- **V. Two Pillars Stay Connected** — ✅ **This is the feature.** Making the CLI
  render the same projection structurally guarantees the findings/graph pillars
  reference identical node/edge identities.
- **VI. Stable, Machine-Readable Contracts** — ✅ The web JSON payload is
  unchanged (FR-005); only the PNG (an untested visual artifact) changes.
- **VII. Test & Traceability Gates** — ✅ New targeted tests for parity + graceful
  degradation. The PNG visual change is recorded here and in the spec
  Clarifications; no `KNOWN_QUIRKS` entry needed (no new heuristic trade-off).

**Result**: PASS. No violations; Complexity Tracking empty.

**Post-design re-check**: PASS — design introduces no new dependency and no new
public surface; `render` signature preserved.

## Project Structure

### Documentation (this feature)

```text
specs/017-unify-cli-graphviz/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── renderer.md
└── checklists/requirements.md
```

### Source Code (repository root)

```text
smartgraphical/core/graph.py                  # REWRITTEN: render from canonical dict
smartgraphical/services/serializers.py        # unchanged (canonical projection source)
smartgraphical/services/analysis_service.py   # unchanged (render_graph wiring)
tests/unit/test_graph_renderer_unified.py     # NEW: parity + graceful degradation
```

**Structure Decision**: Keep `GraphBuilder.render(model, output_label)` signature
and the `service.render_graph(context)` wiring unchanged so no caller is touched.
Internally, `render` calls `model_graph_to_dict(model)` and draws from that dict.
Node ids come from the canonical projection (graphviz-python quotes ids with `:`/
`.` automatically); clustering uses each node's `parent` (the compound type/tile
node). A module-level `GROUP_STYLE` (group→shape/fill) and `EDGE_STYLE`
(kind→color/style) table drives visuals, each with a default branch so unmapped
groups/kinds render rather than drop.

## Approach detail (canonical → graphviz)

1. `graph = model_graph_to_dict(model)`; `nodes = graph["nodes"]`,
   `edges = graph["edges"]`.
2. Partition nodes: compound parents (`group in {type, tile}`) become graphviz
   `cluster_*` subgraphs; child nodes (those carrying a `parent`) are emitted
   inside their parent's cluster; parentless non-compound nodes (e.g. `external`,
   `external_import`) are emitted at top level.
3. Each node drawn with `GROUP_STYLE.get(group, DEFAULT_NODE_STYLE)`, using the
   canonical `id` as the graphviz node id and `label` as the label.
4. Each edge drawn `dot.edge(source, target, **EDGE_STYLE.get(kind, DEFAULT_EDGE_STYLE))`,
   carrying the canonical edge `label` where present.
5. graphviz-None guard and `dot.render(output_label + ".gv", directory="", view=False)`
   preserved.

## Complexity Tracking

> No Constitution violations. Section intentionally empty.
