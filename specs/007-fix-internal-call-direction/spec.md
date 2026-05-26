# Feature Specification: Fix Solidity Internal Call Edge Direction

**Feature Branch**: `007-fix-internal-call-direction`

**Created**: 2026-05-24

**Input**: Fix reversed `function_to_function` edges in Solidity graphs so arrows follow caller -> callee (e.g. `updateStateAndDeposit` -> `deposit`, not the opposite).

## User Scenarios & Testing

### User Story 1 - Correct intra-contract call arrows (Priority: P1)

**Given** a function `updateStateAndDeposit` that calls `deposit` inside the same contract, **When** the user views the full graph, **Then** the internal edge points from `updateStateAndDeposit` to `deposit`.

**Why this priority**: Misleading call direction blocks audit reasoning and contradicts `cross_type_call` semantics fixed in spec 002.

**Independent Test**: Parse a minimal Solidity fixture or `examples/EthMetaVault.sol` and assert exactly one `function_to_function` edge with source caller and target callee for a known call pair.

**Acceptance Scenarios**:

1. **Given** caller body contains `deposit(...)`, **When** graph is built, **Then** edge source is the caller function node and target is `deposit`.
2. **Given** the same contract pair, **When** graph is built, **Then** no reversed edge `deposit` -> caller exists for that call.

---

### User Story 2 - Metadata and derived flags stay consistent (Priority: P2)

**Given** a corrected internal call edge, **When** the serializer derives `calls_internal` and `write_paths`, **Then** outgoing internal edges originate from the caller function node.

**Why this priority**: UI flags and write-path hints must match visible arrow direction.

**Independent Test**: After fix, caller node has `calls_internal=true` and callee node does not gain a spurious outgoing internal edge for that relationship.

**Acceptance Scenarios**:

1. **Given** `updateStateAndDeposit` calls `deposit`, **When** graph JSON is produced, **Then** `updateStateAndDeposit` has outgoing `function_to_function` and `deposit` does not (for that pair).

---

### Edge Cases

- `super.deposit()` inside `deposit`: edge remains caller `deposit` -> callee `deposit` (self-loop) with callsite metadata matching `super.deposit`.
- Event/error names in func list must not become bogus internal edges (existing filter unchanged).
- `cross_type_call` direction from spec 002 must remain caller -> parent callee.

## Requirements

### Functional Requirements

- **FR-001**: Solidity `function_to_function` edges MUST use `source` = caller function, `target` = callee function within the same contract.
- **FR-002**: Call metadata (`callsite`, `args_map`, `line_numbers`) MUST be extracted from the caller body invoking the callee.
- **FR-003**: Reversed callee->caller edges for the same call pair MUST NOT appear in the payload.
- **FR-004**: Regression tests MUST cover a minimal synthetic contract and optionally `examples/EthMetaVault.sol` (`updateStateAndDeposit` -> `deposit`).

### Key Entities

- **function_to_function edge**: Directed call link between two function nodes in one contract compound.
- **func_func_mapping**: Reader index mapping callee name to list of caller names (adapter must invert when emitting edges).

## Success Criteria

### Measurable Outcomes

- **SC-001**: For EthMetaVault (when fixture present), graph shows `updateStateAndDeposit` -> `deposit`, never `deposit` -> `updateStateAndDeposit`.
- **SC-002**: Unit tests for internal call direction pass in CI.
- **SC-003**: `cross_type_call` inheritance tests from spec 002 remain green.

## Assumptions

- Edge direction convention matches C adapter and documented `cross_type_call` semantics (caller -> callee).
- Heuristic call detection (`name(` substring) stays unchanged; only edge emission direction is fixed.
