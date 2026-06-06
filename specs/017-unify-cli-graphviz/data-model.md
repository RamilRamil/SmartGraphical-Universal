# Data Model: Unify CLI graphviz and web renderers

No new runtime entities. The "model" is the shared graph projection and the
visual mapping the renderer applies to it.

## Canonical graph projection (shared, unchanged)

`serializers.model_graph_to_dict(model) -> { "nodes": [...], "edges": [...],
"exploration_hints": {...} }`

### Node (canonical)
- `id` (str): stable identity, e.g. `type:Foo`, `function:Foo.bar`, `state:Foo.x`,
  `tile:<label>` (C), `external:...`. **Shared by web and (now) CLI.**
- `group` (str): one of `type`, `tile`, `function`, `state`, `event`,
  `custom_error`, `modifier`, `external`, `external_import`.
- `label` (str): display label.
- `parent` (str, optional): id of the compound parent (a `type`/`tile` node) when
  the node is nested.
- plus group-specific extras (type_name, source_file, fact fields) — ignored by
  the renderer beyond what the mapping uses.

### Edge (canonical)
- `id`, `source`, `target` (str ids matching node ids).
- `kind` (str): e.g. `function_to_function`, `cross_type_call`,
  `state_to_function[_read|_write]`, `cross_type_state[...]`, `function_to_system`,
  `function_to_object`, and C/bundle kinds (`tile_to_tile`, `bundle_import`,
  `import_dependency`, `function_to_workspace`, `function_to_include_template`,
  `pointer_flow`).
- `label` (str, optional).

## Renderer-local entities (new, in core/graph.py)

### `GROUP_STYLE: dict[str, dict]`
Maps a canonical node `group` to graphviz node attributes (shape, style,
fillcolor, color). Consulted as `GROUP_STYLE.get(group, DEFAULT_NODE_STYLE)`.

| group | intent |
|-------|--------|
| type / tile | compound cluster container (not a drawn node; becomes a cluster) |
| function | rectangle, function fill |
| state | ellipse, var fill |
| event | rectangle, function fill |
| custom_error | note/rectangle |
| modifier | hexagon/diamond |
| external / external_import | parallelogram, system fill |
| (default) | rectangle, neutral fill |

### `EDGE_STYLE: dict[str, dict]`
Maps a canonical edge `kind` to graphviz edge attributes (color, style, arrow).
Consulted as `EDGE_STYLE.get(kind, DEFAULT_EDGE_STYLE)`. Default = solid edge in
the standard edge color, so unknown kinds still render.

## Mapping rules

- A node is a **cluster** iff `group in {type, tile}`.
- A node is **nested** iff it carries a non-empty `parent`; it is drawn inside the
  cluster of that parent id.
- A node is **top-level** otherwise (e.g. `external`, `external_import`).
- Every edge is drawn `source -> target` with its mapped style; no edge is
  dropped for an unknown kind.

## Invariants (validation rules)

- CLI rendered node-id set == canonical projection node-id set (minus pure
  cluster-container duplication) — pinned by the parity test (SC-001).
- Web payload unchanged (SC-002) — the renderer only *reads* the projection.
- No edge or node silently dropped (Principle II) — defaults guarantee rendering.
