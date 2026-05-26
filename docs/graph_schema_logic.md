# Graph Schema Construction Logic

This document explains how SmartGraphical builds the interactive graph shown on
the `Scan detail -> Graph` tab.

## 0. Scope and related docs

- Scope: implemented graph behavior for the current production serializer and UI.
- Solidity scans: meta-task **`0`** (alias **`all`**) runs every `RuleSpec` from `build_rule_registry()` (tasks `1`..`15`), then serializes the graph when the pipeline requests it.
- C/Node target profile and best-practice contract: `docs/graph_schema_logic_c.md`.
- Rust/Soroban target profile and serializer alignment notes: `docs/graph_schema_logic_rust.md`; rule catalog scaffold: `docs/rust_stellar/soroban_rules_catalog.json`.
- This file is the source of truth for currently implemented graph semantics.

## 1. End-to-end flow

1. Source code is parsed by an adapter (`solidity`, `c_base`, or `rust_stellar`).
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

### 2.6 Multi-file bundle (combined artifact) and `source_file`

When the analyzer target is a **bundle** (directory on disk containing
`sg_bundle_manifest.json` and member files), the graph is built by analyzing
each member file, then **merging** per-file graph payloads with stable id
prefixes. See `merge_bundled_model_summaries` and
`apply_bundle_source_prefix_to_model_summary_graph` in
`smartgraphical/services/serializers.py`.

**On-disk manifest** (`sg_bundle_manifest.json`):

| Field | Meaning |
|-------|---------|
| `version` | `1` = flat layout (member `path` is a single path segment, effectively basename within the bundle). |
| `version` | `2` with `"layout": "tree"` = member `path` is a POSIX relative path (may contain `/`). |
| `members` | Array of `{ "path", "sha256" }` listing every source file in the bundle. |
| `solidity_remappings` | Optional: JSON array of prefix maps for Solidity imports, e.g. `[["@vendor/", "contracts/vendor/"]]` or `[{ "prefix": "@oz/", "path": "lib/oz/" }]`. Longest prefix wins; applied before resolving an import to a manifest `path` (see `_apply_solidity_remappings` in `web_api.py`). Ignored for non-Solidity bundles. |
| `c_include_prefixes` | Optional (C bundles): JSON array of POSIX directory prefixes. After resolving a quoted `#include` relative to the consumer file, the resolver also tries `prefix/rel` for each prefix, with the same traversal-safety checks as other bundle path logic (`_normalize_manifest_c_include_prefixes`, `_resolve_c_provider_rel` in `web_api.py`). |

**`source_file` on nodes (and merge tag):**

After merge, each node carries `source_file` equal to that member's **`path`**
string from the manifest — not only the basename. For flat bundles this is
usually the same as the filename (e.g. `Token.sol`). For tree bundles it is
the full relative path (e.g. `contracts/Token.sol`). The UI and downstream
logic should treat `source_file` as the stable **bundle-relative** identifier
for the file that produced the node.

**Merged artifact metadata:** `model_summary.artifact.bundle_members` is the
ordered list of those manifest paths (see `merge_bundled_model_summaries`).

**Cross-file bundle edges** (Solidity imports, C quoted/includes between member
`.c`/`.h`, Rust `mod`/`crate` links) are added in `smartgraphical/services/web_api.py`
after merge. They resolve provider/consumer members using manifest paths and
relative import/include strings so duplicate basenames in different
directories can still match when paths are unambiguous. **Rust:** file-module
``mod foo;`` resolves under the consumer file's directory, optionally extended
by segments for each enclosing inline ``mod bar { ... }`` block; ``super::``
checks that directory first, then one path segment up; ``crate::`` is restricted
to members under a single inferred crate root when the bundle lists exactly one
qualifying `lib.rs` or `main.rs` path (see `web_api._rust_pick_crate_root_for_consumer`).
**Solidity:** unqualified imports that match more than one member basename do not create a
synthetic edge.

**Solidity import scan:** Block comments `/* ... */` are removed before import path extraction so commented-out `import` lines do not create bundle edges (`_strip_solidity_block_comments`). Each logical line is then stripped of trailing `//` comments in a quote-aware way (`_solidity_strip_line_comment`) so paths like `"./a//b.sol"` are not truncated naively at `//`. The `import ... ;` match may span lines (`re.DOTALL`), so `import { Symbols } from "path";` and multiline braced imports are covered (`_solidity_file_import_paths`, `_solidity_clause_to_paths`).

**Bundle graph hints:** When cross-file edges are skipped (ambiguous basename, unresolved import/include/module), `graph.exploration_hints.bundle_edge_resolution` may list non-zero integer counts per reason, for example `skipped_solidity_ambiguous_basename`, `skipped_solidity_unresolved_import`, `skipped_c_ambiguous_basename`, `skipped_c_unresolved_include`, `skipped_rust_unresolved_module` (`_apply_bundle_edge_hints`).

**HTTP ingest:** tree layout is selected when the client sends
`bundle_paths_json` with `POST /api/artifacts/bundle`. See
`docs/bundle_folder_upload_iterations.md`.

## 3. Solidity adapter edge sources

File: `smartgraphical/adapters/solidity/adapter.py`

Edge kinds used by graph (Solidity adapter, schema `1.1`):

- `state_to_function_read` — state variable is read by function
- `state_to_function_write` — state variable may be written by function
- `function_to_function` — caller function to callee function within the same contract (same direction as `cross_type_call`: caller -> callee)

**State variables (Solidity reader):** `ContractReader.extract_variables` matches declaration lines by type prefix: `mapping`, `address`, `string`, `bool`, `bytes<N>`, `uint<N>`, `int<N>`, plus `Lib.Type visibility name` for user-defined storage (e.g. `ExitQueue.History internal _exitQueue`). Bare `uint` without digits is covered by `uint<N>` with optional digits. Legacy keyword list `string/uint/mapping/address/bytes` alone is insufficient for `uint256` / `uint128` fields.
- `function_to_system`
- `function_to_object`
- `function_to_event`
- `cross_type_state_read` / `cross_type_state_write` — parent state, child function
- `cross_type_call` — child function (caller) to parent function (callee) for inherited internal calls detected in the child body

Legacy (older payloads only; UI treats `state_to_function` as read):

- `state_to_function`, `cross_type_state`

Contract reference: `specs/001-fix-solidity-state-writes/contracts/graph-state-access-v1.1.md`.

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

- Graph tab is enabled for scans run with `task = 0` or legacy `all` (HTTP meta id `0`; CLI run-all uses `0` / `all` and renders the graph; graph-only CLI id is `99`).
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
3. `graph_schema_logic_rust.md` tracks Rust/Soroban target schema and how it maps onto the shared graph payload contract.
4. When payload fields or `kind` semantics change, update the base doc and any affected target doc (`graph_schema_logic_c.md` or `graph_schema_logic_rust.md`) in the same PR.
5. New Solidity rule tasks (`RuleSpec` in `build_rule_registry()`) should land with updates to `docs/solidity_rules_catalog.json`, `tests/fixtures/solidity_task_coverage.json`, and `docs/rules_ru_solidity.md`; adjust Section 5 here if CLI/HTTP `all` behavior description changes.
