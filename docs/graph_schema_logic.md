# Graph Schema Construction Logic

This document explains how SmartGraphical builds the interactive graph shown on
the `Scan detail -> Graph` tab.

## 0. Scope and related docs

- Scope: implemented graph behavior for the current production serializer and UI.
- C/Node target profile and best-practice contract: `docs/graph_schema_logic_c.md`.
- This file is the source of truth for currently implemented graph semantics.

## 1. End-to-end flow

1. Source code is parsed by an adapter (`solidity` or `c_base`).
2. Adapter builds a `NormalizedAuditModel`:
   - `types`
   - `functions`
   - `state_entities`
   - `events` (for Solidity)
   - `call_edges`
3. `web_api.graph(...)` returns `model_summary`.
4. `model_summary_to_dict(...)` calls `model_graph_to_dict(...)`.
5. Frontend fetches `GET /api/scans/{id}/graph` and renders with Cytoscape.

## 2. Backend graph payload (serializer)

File: `smartgraphical/services/serializers.py`

Main function: `model_graph_to_dict(model) -> { "nodes": [...], "edges": [...] }`

### 2.1 Node groups

- `type`: compound parent node per contract or translation unit.
- `function`: executable function nodes.
- `modifier`: declared Solidity modifiers (for example `onlyOwner`).
- `state`: state variables / object instances / struct-like entities.
- `event`: Solidity events.
- `external`: fallback for unresolved edge endpoints.

### 2.2 Stable ids

IDs are deterministic and namespaced:

- `type:<type>`
- `function:<type>.<function>`
- `modifier:<type>.<modifier>`
- `state:<type>.<state>`
- `event:<type>.<event>`
- `external:<name>`

### 2.3 Solidity-specific modifier handling

Declared modifier definitions are marked by reader with
`__declared_modifier__` in modifiers metadata.

Serializer behavior:

1. Collect declared modifier names per type.
2. Create explicit `modifier` nodes for those names.
3. For each function node:
   - include `modifier_details` (all signature modifiers except marker),
   - include `modifier_ring_details` (subset that are declared modifiers).

This powers nested compound rings in frontend.

### 2.4 Function metadata in graph

Each function node may contain:

- `visibility`
- `is_entrypoint`
- `source_body` (function body text for code panel on click)
- `modifier_details`
- `modifier_ring_details`
- derived booleans after edge pass:
  - `calls_internal`
  - `calls_contract`
  - `calls_system`
  - `calls_event`

### 2.5 Endpoint resolution order

For each edge endpoint `(type_name, target_name)`:

1. typed function id
2. typed state id
3. typed event id
4. typed modifier id
5. unqualified function lookup
6. unqualified state lookup
7. unqualified event lookup
8. unqualified modifier lookup
9. fallback to `external:<target_name>`

This guarantees every edge references existing nodes.

## 3. Solidity adapter edge sources

File: `smartgraphical/adapters/solidity/adapter.py`

Edge kinds used by graph:

- `state_to_function`
- `function_to_function`
- `function_to_system`
- `function_to_object`
- `function_to_event`
- `cross_type_state`
- `cross_type_call`

Important detail:

- Event names are present in reader internals for reachability, but adapter
  filters bogus event-as-source rows and adds explicit `function_to_event`
  edges from `emit <EventName>(...)`.

## 4. Frontend rendering logic

File: `frontend/src/components/GraphView.tsx`

### 4.1 Element construction

- Basic nodes/edges come from backend payload.
- For each function with `modifier_ring_details`, frontend injects nested
  compound helper nodes `group = "modifier_ring"`:
  - one ring per modifier
  - each ring is parent of next ring
  - innermost ring is parent of function node

This allows multiple modifier rings around one function.

### 4.2 Visual conventions

- Function node: blue fill.
- Entrypoint function: orange border.
- Modifier node: dark center with colored border.
- Modifier rings: transparent fill, colored border.
- Event node: purple hexagon.
- External fallback node: gray diamond.

Edges are styled by `kind` (color and line style), for example:

- `function_to_event`: purple
- `function_to_object`: orange dashed
- `function_to_system`: violet dotted

### 4.3 Click behavior

- Clicking node highlights connected edges.
- Clicking ring resolves to underlying function node for details panel.
- Function details panel shows:
  - metadata
  - modifiers
  - outgoing call summary
  - `Code` block from `source_body`

## 5. Availability and persistence

- Graph tab is enabled for scans run with `task = all`.
- Graph JSON is persisted per scan under `workspace/scans/.../graph.json`.
- Older scans may not contain full node/edge payload and should be re-run.

## 6. Known fallback behavior

If a target symbol cannot be mapped to function/state/event/modifier,
serializer creates `external:<name>` node. This is intentional to avoid
dropping edges and hiding potential audit-relevant paths.


## 7. Document alignment policy

To keep docs consistent:

1. `graph_schema_logic.md` tracks implemented behavior.
2. `graph_schema_logic_c.md` tracks C/Node target schema and migration guidance.
3. When payload fields or `kind` semantics change, update both files in the same PR.
