# Rust/Soroban Graph Schema Construction Logic

This specification defines the logic and structural requirements for constructing a high-fidelity graph schema representing the Rust/Soroban smart contract environment. It establishes the transformation rules for converting the Stellar Rust dialect into a directed graph model that captures logic flow, storage dependencies, and security constraints.

## Scope and relation to other docs

- This file defines the Rust/Soroban **target** schema, stable-id strategy, and domain mapping for graph construction and rule-oriented signals.
- Target Soroban rule catalog (structured, implementation-agnostic until adapter lands): `docs/rust_stellar/soroban_rules_catalog.json`.
- General Rust language helper catalog (tasks **209-223**; **209-216** language ergonomics/safety, **217-223** Base Azul-oriented review heuristics, plus optional `review_scenarios` / `review_checklist` JSON fields): `docs/rust/language_rules_catalog.json`.
- **Implemented** graph behavior for the current production stack (serializers, API, UI) is documented in `docs/graph_schema_logic.md`.
- When Rust/Soroban payload fields, `group` names, or `kind` semantics become implemented, mirror the relevant contract into the base doc in the **same** change (see `graph_schema_logic.md` section 7).

## Implementation status

- **Implemented today (shared graph engine):** building the graph from `NormalizedAuditModel` via `smartgraphical/services/serializers.py::model_graph_to_dict`, base node groups (`type`, `function`, `state`, `event`, `external`, plus Solidity-only `modifier`), mandatory edge endpoint resolution, and frontend consumption as in the base doc.
- **Not implemented today for Rust/Soroban:** a dedicated `rust_soroban` (or equivalent) adapter feeding that model, Soroban-specific `group`/`kind` extensions, and UI styles beyond the shared defaults. The sections below are **target** guidance until wired in code.
- **Integration note:** Rust rules and graph UX should converge on the same JSON node/edge shape the serializer already guarantees (required fields below), optionally extended with Soroban metadata and documented experimental flags if needed.

## Schema contract alignment (shared with product)

To stay compatible with `model_graph_to_dict` and `GraphView`, any Rust/Soroban increment should honor:

### Required fields

- **Node:** `id`, `group`, `label`
- **Edge:** `id`, `source`, `target`, `kind`

### Versioning

- Recommend top-level `graph_schema_version` (for example `"1.0"` or `"1.x"`) when the Rust profile ships, following the compatibility rules in `graph_schema_logic_c.md` section 2.3 (optional additive fields; breaking changes bump major).

### Mapping: Soroban taxonomy to base `group`

Until dedicated Rust-only groups exist in the UI, bind Soroban concepts to the serializer vocabulary:

| Soroban / doc concept | Preferred base `group` | Notes |
| --------------------- | ---------------------- | ----- |
| Contract / module root (`#contract`) | `type` | Compound scope for one contract TU / logical type name |
| Callable surface (`#contractimpl`) | `function` | Public and internal fn nodes as resolved by adapter |
| Storage slot / ledger-backed cell | `state` | Distinguish instance/persistent/temporary via metadata or labels |
| `#contracttype` / Soroban data shapes | `type` or nested under contract | If the UI stays flat, use `type` with clear `label` prefix |
| `#contractevent` | `event` | Match Solidity event rendering where possible |
| External contract id / unresolved target | `external` | Preserve edges per base fallback policy |

### Stable IDs (Rust/Soroban profile, target)

Identifiers must remain deterministic within a scan/workspace:

- `type:<canonical_contract_name>` (or hashed path if collisions)
- `function:<type_scope>.<fn_name>[.<collision_suffix>]`
- `state:<type_scope>.<storage_key_or_slot_descriptor>`
- `event:<type_scope>.<event_name>`
- `external:<ledger_address_or_symbol>` or `external:<label>` aligned with resolver output

Separate **wasm install (code hash)** and **deployment address** concerns in metadata (see domain section 2.2): both may appear as attributes on `type`/instance nodes rather than replacing `id` unless the product standardizes composite ids.

### Proposed edge `kind` values (target)

Align names with existing adapters where semantics match; extend only with new documented strings:

- `function_to_function`: ordinary call graph inside contract
- `function_to_object` or `cross_type_call`: cross-contract invokes (`env.invoke_contract`, `try_invoke_contract`)
- `function_to_event`: `env.events().publish(...)` linkage
- `state_to_function` / `function_to_object`: reads/writes mapped to storage API (finalize direction in implementation to match serializer conventions)
- Auth paths: dedicated `kind` or `label`/`metadata` (for example dependency from `require_auth` to function) chosen and frozen when the Rust adapter lands

Unresolved endpoints should follow the base serializer policy (`external:<name>`) so edges are never dropped silently.

---

## 1. End-to-end pipeline: source parsing to graph model

The construction pipeline initiates with a deep parse of the contract source to extract the execution context and functional dependencies.

### 1.1 Source analysis and extraction

The `rust_soroban` adapter (target) begins by validating foundational markers that define the "Stellar Rust dialect." The schema construction logic must identify:

- **The `no_std` attribute:** mandatory indicator that the contract excludes the Rust standard library for a deterministic execution profile.
- **`wasm32v1-none` target:** foundational for Rust v1.84.0+. The adapter verifies this target to ensure elimination of OS dependencies and compatibility with the Soroban Host.

### 1.2 Macro-driven model construction

Core entities (nodes) are derived from attribute macros:

- `#contract`: root scope for contract structure (maps to base `type` node).
- `#contractimpl`: logic entry points and internal function nodes (`function`).
- `#contracttype`: structured data (`type`/`state` adjunct nodes as resolved).
- `#contractevent`: event schema (`event`).

### 1.3 Environment (`Env`) contextualization

The adapter identifies interactions by tracing `Env`:

- Ledger access via `env.ledger()`.
- Storage via `env.storage()`.
- Events via `env.events()`.
- Cross-contract relationships via `env.invoke_contract()` (and variants).

---

## 2. Node taxonomy and payload structure

### 2.1 Standardized node groups (domain view)

Five primary Soroban-facing categories (mapped to base `group` above):

1. Contract/function nodes: logic blocks within `#contractimpl`.
2. Storage nodes: tiered storage model (instance / persistent / temporary).
3. Type nodes: native and custom types (`Address`, `Symbol`, `Vec`, `Map` from `#contracttype`).
4. Event nodes: `#contractevent`, published via `env.events().publish()`.
5. External/cross-contract nodes: external IDs and `Address` identifiers for cross-contract calls (`external`).

### 2.2 Stable ID generation logic (lifecycle)

The graph distinguishes deployment phases in metadata:

- **Code hash (template id):** produced at install; identifies Wasm bytecode; use to correlate instances sharing logic.
- **Unique address:** produced at deployment; identifies a ledger instance.

### 2.3 Rust-specific metadata payloads

| Rust syntax | Graph attribute / classification | Technical nuance |
| ----------- | -------------------------------- | ---------------- |
| `#contractimpl` | Logic entry point | Publicly surfaced functions |
| `require_auth()` | Simple security constraint | Identity for current invocation |
| `require_auth_for_args()` | Granular security constraint | Identity for argument sets |
| `env.authorize_as_current_contract()` | Sub-contract authorization | Child-invocation permissions |
| `panic_with_error!` | Fallible state attribute | Structured controlled exit |
| `panic!` | Critical risk attribute | Uncontrolled failure surface |

### 2.4 Storage tier definitions

| Storage type | Archival TTL logic | Primary use case | Cost profile |
| ------------ | ------------------ | ---------------- | ------------ |
| Instance | Tied to contract instance TTL | Configuration, admin addresses | Moderate; whole entry loads on interaction |
| Persistent | Independent entry TTL | Balances, claimable state | Highest; archival/restoration |
| Temporary | Expires without archival | Oracle feeds, short-lived state | Lowest; no archival |

---

## 3. Edge source mapping and relationships

### 3.1 Internal function call graphs

Edges capture execution flow. Treat `env.invoke_contract` / `env.try_invoke_contract` as sources for directed edges from the calling function node to the target contract instance node (or `external` when unresolved).

### 3.2 Functional data flow (function-to-storage)

Edges between functions and storage slots follow access API:

- `.instance()` → instance storage edge (document final `kind` at implementation time).
- `.persistent()` → persistent storage edge.
- `.temporary()` → temporary storage edge.

### 3.3 Event propagation (function-to-event)

Any `env.events().publish()` call is an edge source from the originating function to the event node (`function_to_event` where aligned with Solidity).

### 3.4 Authorization dependencies

- **Simple auth edges:** from `Address::require_auth()` to dependent function or address node.
- **Granular auth edges:** from `require_auth_for_args()` to parameter validation dependencies.

---

## 4. Visualization logic and style conventions

### 4.1 Node visual encoding

- Storage tiers: distinct shapes or colors for instance, persistent, temporary.
- Archived state: dim nodes past TTL; surface a restoration path when the client supports it.

### 4.2 Edge stroke styles

- Atomic cross-contract calls: solid lines for standard `invoke_contract`.
- Auth checks: bold labels or markers on `require_auth` dependency paths.
- Upgradability: dashed upgrade edge across logic version nodes for `update_current_contract_wasm()` transitions.

---

## 5. Architectural limitations and fallbacks

### 5.1 Unbounded data risks (DoS flagging)

Flag large or unbounded structures attached to **instance** storage: the host loads the full instance entry per interaction. Protocol limits (for example entry size and instruction budget) should drive warnings when exceeded or implied.

### 5.2 Archival barrier

Treat archived ledger state as a visibility barrier; restoration footprint may be surfaced when derivable from client/SDK semantics.

### 5.3 Determinism constraints

Flag host-only or non-deterministic constructs (wall clock, restricted floating-point) as safety annotations for ledger-fork risk triage.

### 5.4 Dependency resolution fallbacks

`create_import!`-style workflows without hard versioning deserve metadata cross-checks (for example imported contract metadata vs deployed code hash) to flag drift.

---

## 6. Validation and QA (target)

Before shipping a Rust graph profile:

1. Unique `node.id` / `edge.id`.
2. Every edge endpoint exists in the node set.
3. No invalid `parent` cycles for compound nodes.
4. Unknown `group`/`kind` either avoided or flagged `experimental_*` consistently with the C profile.

Contract tests against representative Soroban contracts are recommended when the adapter exists.
