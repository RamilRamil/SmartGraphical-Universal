# Research: Accurate Solidity State Read/Write Detection

**Feature**: `001-fix-solidity-state-writes`  
**Date**: 2026-05-21  
**Scope decision**: **Variant B** — fix `state_writes` / `mutations` **and** split graph edges into read vs write.

## R1: Root cause of false writes in view functions

**Decision**: Treat current behavior as three independent heuristic bugs in `_collect_mutations` / `_collect_state_accesses` (`smartgraphical/adapters/solidity/adapter.py`).

**Rationale** (validated on `KeeperRewards.sol`):

| Pattern | Example | Why flagged today |
|---------|---------|-------------------|
| Comparison `=` | `rewards[vault].nonce != 0` | `'=' in stmt` matches `!=` |
| Local load | `uint256 nonce = rewards[vault].nonce` | `rewards` + `=` in same statement |
| Substring name | `nonce + 1 < rewardsNonce` | `'rewards' in stmt` matches inside `rewardsNonce` |

**Alternatives considered**:

- Full Solidity AST (solc/slang): rejected for v1 — high cost, parser dependency, out of spec scope.
- Disable mutations for all `view`/`pure`: necessary but insufficient alone (non-view functions still need R1 fixes).

## R2: Whole-token matching for state variable names

**Decision**: Match state identifiers with word-boundary rules (regex `(?<![A-Za-z0-9_])name(?![A-Za-z0-9_])` or equivalent scan), applied before classifying read vs write.

**Rationale**: Prevents `rewards` from matching `rewardsNonce`, `rewardsRoot`, `prevRewardsRoot`, etc.

**Alternatives considered**:

- Longest-match among `state_names`: fragile when two names share prefixes; still needed as secondary tie-break only.

## R3: Distinguishing assignment from comparison and local initialization

**Decision**: A statement is a **write** to `V` only if:

1. `V` appears as a whole token (or via tracked storage alias — see R4), and  
2. The statement contains a **write operator** at the assignment position: lone `=`, `+=`, `-=`, `*=`, `/=`, etc., excluding `==`, `!=`, `<=`, `>=`, `=>` (Solidity lambda), and excluding `==` in `event` signatures (N/A in body).  
3. The statement is **not** a local/memory declaration that only **reads** `V` on the RHS (pattern: `Type [storage|memory]? name = ...V...` where LHS does not reference `V` as write target).

**Rationale**: Covers FR-001, FR-002 without AST.

**Alternatives considered**:

- Strip all `!` before checking `=`: breaks valid negated assignments (rare); prefer multi-char operator denylist.

## R4: Writes through `storage` references bound to mapping slots

**Decision**: Within a function body, track bindings `storage <id> = V[...]` (heuristic regex). Subsequent assignments to `<id>.<field>` count as writes to `V`.

**Rationale**: `KeeperRewards.harvest` updates `rewards` via `lastReward.nonce` / `lastReward.assets` without literal `rewards` on LHS of field writes.

**Alternatives considered**:

- Require literal `rewards[` on every write line: misses real mutations (unacceptable per FR-005).

## R5: `view` / `pure` functions

**Decision**: If function modifiers include `view` or `pure`, force **zero** storage `mutations` / write-classified `NormalizedStateAccess` entries (reads still allowed).

**Rationale**: Aligns with Solidity semantics for reviewers; eliminates entire class of false positives even if heuristics regress on a line.

**Alternatives considered**:

- Trust heuristics only: insufficient for `isCollateralized`-style lines.

## R6: Graph edge model (Variant B)

**Decision**: Introduce explicit edge kinds (additive, schema `1.1`):

| Kind | Direction | Meaning |
|------|-----------|---------|
| `state_to_function_read` | state → function | Function reads variable |
| `state_to_function_write` | state → function | Function may write variable |
| `cross_type_state_read` | parent state → child function | Inherited/read across types |
| `cross_type_state_write` | parent state → child function | Inherited/write across types |

Stop emitting undifferentiated `state_to_function` / `cross_type_state` for **new** Solidity graphs after migration; keep serializer accepting legacy kinds for one release.

**Rationale**: FR-006; UI can filter writers vs readers on state inspector and edge styling.

**Alternatives considered**:

- Single edge + `access` field on edge payload: equivalent expressiveness; chosen kinds match existing `kind`-per-edge pattern in Cytoscape payload.
- Only enrich function node `state_reads` / `state_writes` without new edges: insufficient for “Used by functions” panel on state nodes (today uses edges only).

## R7: Replacing `extract_var_func_mapping` for Solidity edges

**Decision**: Build state↔function edges from per-function `read_accesses` / write list derived from improved `_collect_state_accesses`, not from `ContractReader.extract_var_func_mapping` substring scan.

**Rationale**: `var_func_mapping` cannot distinguish read vs write and shares substring bugs.

**Alternatives considered**:

- Patch `extract_var_func_mapping` only: cannot deliver Variant B without duplicate logic.

## R8: Frontend consumption

**Decision**: Update `GraphView.tsx` and `frontend/src/api/types.ts`:

- State inspector: list **Readers** and **Writers** from new edge kinds (fallback: treat legacy `state_to_function` as read-only for display).
- Highlight modes: `sg-state-write` unchanged (driven by `state_writes` on function nodes).
- Legend: add buckets for read vs write state edges (optional same color, different line style).

**Rationale**: Minimal UI scope per spec assumptions.

## R9: Testing strategy

**Decision**:

1. Unit tests for new helper functions (comparison, token match, storage alias, view filter).  
2. Integration test: minimal Solidity snippet fixture mirroring `KeeperRewards` patterns → `build_normalized_model` → `model_graph_to_dict` assertions on `state_writes` and edge kinds.  
3. Extend `tests/unit/test_serializers.py` for new edge kinds.

**Rationale**: SC-004; regression lock for SC-001–SC-003.

## R10: Documentation and schema version

**Decision**: Bump `graph_schema_version` to `"1.1"` when new edge kinds ship; document in `docs/graph_schema_logic.md` with migration note for frontend.

**Alternatives considered**:

- Stay on `1.0` with undocumented kinds: breaks consumers relying on version field.
