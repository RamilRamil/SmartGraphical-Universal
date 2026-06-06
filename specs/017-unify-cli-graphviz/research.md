# Research: Unify CLI graphviz and web renderers

Phase 0 — no open `NEEDS CLARIFICATION`. The one nuance (PNG visual change) was
resolved in the spec Clarifications: structural parity, not pixel preservation.

## Decision 1 — Standardize on `model_graph_to_dict`

**Decision**: The CLI renderer consumes `serializers.model_graph_to_dict(model)`
(the same projection the web uses), not a parallel walk of `model.types` /
`model.call_edges`.

**Rationale**: That projection already handles all three languages, the C `tile:`
remapping, bundle edges, write-path derivation, external/unresolved node classes,
and a validation/normalization pass. Re-using it is what makes drift structurally
impossible (Principle V). The CLI's `func_X_Y` scheme is a strictly poorer,
divergent re-implementation.

**Alternatives considered**:
- Extract a new third "render model" both consume — unnecessary; the canonical
  dict already IS that shared model.
- Keep two renderers but add a parity test — does not remove the duplication
  (fails SC-004) and lets them drift between test runs.

## Decision 2 — Node ids with `:` / `.` in graphviz

**Decision**: Use the canonical ids (`type:Foo`, `function:Foo.bar`, `tile:...`,
`external:...`) directly as graphviz node ids.

**Rationale**: The `graphviz` Python package quotes node ids containing special
characters automatically when generating DOT, so `:`/`.`/spaces are safe. This
avoids inventing yet another id scheme and keeps CLI ids identical to web ids
(the parity requirement). `sanitize_graph_token` is no longer needed for node ids
(may still be used for cluster names if desired).

**Verification**: render a fixture with graphviz installed and confirm no DOT
syntax error; covered by the render smoke part of the graceful/real test (skipped
when graphviz absent).

## Decision 3 — Clustering via canonical `parent`

**Decision**: Build graphviz `cluster_*` subgraphs from compound parent nodes
(`group in {type, tile}`); place each child node (those with a `parent`) inside
its parent cluster; emit parentless non-compound nodes at top level.

**Rationale**: The canonical projection already encodes the compound hierarchy
(the same one cytoscape uses for its compound nodes), so clusters mirror the web
grouping exactly. External/import nodes are intentionally top-level in both.

## Decision 4 — Data-driven visual mapping with defaults

**Decision**: Module-level `GROUP_STYLE` (group → graphviz shape/fill) and
`EDGE_STYLE` (kind → color/style), each consulted via `.get(key, DEFAULT)` so an
unmapped group/kind renders with a sensible default instead of being dropped.

**Rationale**: New canonical groups/kinds appear over time (bundles already added
several). A mapping-with-default keeps the renderer forward-compatible and honors
Principle II (don't silently drop signals). Known vocabulary today: groups =
{type, tile, function, state, event, custom_error, modifier, external,
external_import}; edge kinds include function_to_function, cross_type_call,
state_to_function(_read/_write), cross_type_state(_read/_write),
function_to_system, function_to_object, plus C/bundle kinds
(function_to_workspace, function_to_include_template, tile_to_tile, bundle_import,
import_dependency, pointer_flow).

## Decision 5 — Preserve signature, wiring, and graceful degradation

**Decision**: Keep `GraphBuilder.render(model, output_label)` and
`AnalysisService.render_graph(context)` exactly as-is; keep the `graphviz is None`
guard + message and the `dot.render(output_label + ".gv", directory="", view=False)`
call.

**Rationale**: No caller changes (CLI, service) and the optional-dependency
contract (Technology Constraints) is untouched.

## Open risks

- A node in the canonical projection might lack a `parent` field for a group we
  expect to be nested. Mitigation: treat "has non-empty `parent`" as the nesting
  signal; anything else is top-level. Verified by the parity test enumerating all
  fixture node ids.
- graphviz not installed in the dev/CI env → the real-render assertion must skip,
  not fail. The parity test (dict-level) does not need graphviz.
