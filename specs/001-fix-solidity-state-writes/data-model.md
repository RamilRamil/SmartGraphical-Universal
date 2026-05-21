# Data Model: State Access Classification

**Feature**: `001-fix-solidity-state-writes`

## Entities

### StateVariable (existing)

- **Source**: `NormalizedStateEntity` in `NormalizedType.state_entities`
- **Key**: `name` (e.g. `rewards`), `owner` (contract name)
- **Graph node**: `group = "state"`, `kind = "state_variable"`

### Function (existing)

- **Source**: `NormalizedFunction`
- **New derived flags** (logical, may remain implicit):
  - `reads_state: set[str]` — entity names read
  - `writes_state: set[str]` — entity names written

### StateAccessRecord (refined use of `NormalizedStateAccess`)

| Field | Type | Description |
|-------|------|-------------|
| `entity_name` | string | Whole-token matched state variable |
| `access_kind` | `"read"` \| `"write"` | Classification |
| `source_statement` | string | Normalized statement fragment (audit trail) |

**Rules**:

- At most one write record per `(function, entity_name, statement)` deduped by statement text.
- `view`/`pure` functions: only `access_kind = "read"` allowed.

### NormalizedFunction.mutations (existing field, semantics tightened)

- List of **write** statement strings only (subset of write `StateAccessRecord.source_statement`).
- Consumed by Solidity rules (`state_mutation`, `outer_calls`, `staking`).
- Empty for `view`/`pure`.

### StorageAliasBinding (internal, parse-time only)

| Field | Type | Description |
|-------|------|-------------|
| `alias_id` | string | Local name (`lastReward`) |
| `root_var` | string | State variable (`rewards`) |
| `binding_stmt` | string | e.g. `Reward storage lastReward = rewards[msg.sender]` |

Used only during single-function body analysis; not serialized to graph.

## Relationships

```text
Contract (NormalizedType)
  ├── StateVariable*
  └── Function*
        ├── StateAccessRecord*  (reads + writes)
        └── mutations[]         (writes only, denormalized)

Graph (serialized)
  StateVariable --[state_to_function_read]--> Function
  StateVariable --[state_to_function_write]--> Function
```

Cross-inheritance:

```text
Parent.StateVariable --[cross_type_state_read|write]--> Child.Function
```

## State transitions (classification pipeline)

```text
function body
  → split statements (;)
  → extract view/pure? → if yes, writes = ∅
  → detect storage aliases (storage id = V[...])
  → for each statement:
        for each state name (whole token):
          if write operator targets V or alias of V → write
          elif V referenced → read
  → emit read_accesses, mutations
  → emit call_edges (read/write kinds)
```

## Validation rules

| ID | Rule |
|----|------|
| DM-001 | `access_kind=write` implies statement passes write-operator + target rules |
| DM-002 | `view`/`pure` ⇒ no write records for any state entity |
| DM-003 | `entity_name` must be in contract `state_entities` names list |
| DM-004 | Write via alias requires prior binding in same function body |
| DM-005 | Graph edge `state_to_function_write` exists only if function has write access to that entity |

## Graph payload (function node fields, unchanged names)

| Field | Content after fix |
|-------|-------------------|
| `state_reads` | Sorted unique `entity_name` from read accesses |
| `state_writes` | Sorted unique write statements (or entity names — **plan**: keep statement strings for panel detail, entity names deduped for counts) |

**Plan detail**: `state_reads` on graph node = list of **entity names** (today from `read_accesses.entity_name`). `state_writes` = list of **statements** (today from `mutations`). Align serializer with `read_accesses` / `mutations` after adapter fix.
