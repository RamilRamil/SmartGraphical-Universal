# Contract: Graph State Access Edges (v1.1)

**Version**: `graph_schema_version: "1.1"` (additive over `1.0`)  
**Profile**: Solidity adapter → `model_graph_to_dict` HTTP/API payload

## New edge kinds

### `state_to_function_read`

- **source**: state node id (`state:<Type>:<var>`)
- **target**: function node id (`func:<Type>:<fn>`)
- **Semantics**: Function may read storage variable at runtime (includes `view`).

### `state_to_function_write`

- **source**: state node id
- **target**: function node id
- **Semantics**: Function may write storage variable (excludes `view`/`pure` for that var).

### `cross_type_state_read` / `cross_type_state_write`

- Same semantics as above for parent type state → child type function (inheritance bridge).

## Deprecated (compatibility)

| Legacy kind | Migration |
|-------------|-----------|
| `state_to_function` | Treat as **read** in UI if no `*_read`/`*_write` edges present for that pair |
| `cross_type_state` | Treat as **read** under same fallback rule |

New analyzer output MUST NOT emit legacy kinds for Solidity once feature ships (tests enforce).

## Function node fields (unchanged keys)

```json
{
  "state_reads": ["rewards", "rewardsNonce"],
  "state_writes": ["rewards[vault] = Reward({...})"]
}
```

- `state_reads`: array of **state variable names** (strings).
- `state_writes`: array of **source statement** strings classified as writes (may be empty).

## Invariants

1. If `state_writes` mentions entity `V` (whole-token), there MUST be a `state_to_function_write` edge from `V` to that function (unless graph merged/filtered).
2. If function is `view`/`pure`, `state_writes` MUST be `[]` and MUST NOT have incoming `state_to_function_write` edges.
3. Read-only usage MUST produce `state_to_function_read` and MUST NOT produce `state_to_function_write`.

## Consumer requirements (frontend)

| Component | Behavior |
|-----------|----------|
| State node panel | Sections: **Readers**, **Writers** (from edge kinds) |
| Write highlight | Continue using `state_writes.length > 0` on function nodes |
| Legend | Register `state_to_function_read` / `state_to_function_write` under state edge bucket (split or shared) |

## Non-goals (v1.1)

- Per-edge statement text or line numbers (future).
- Field-level granularity (`rewards[v].nonce` vs `rewards[v].assets`) — variable-level only.
