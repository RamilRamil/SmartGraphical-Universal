# Feature Specification: Solidity State Variable Type Coverage

**Feature Branch**: `008-solidity-state-var-types`

**Created**: 2026-05-24

**Input**: Graph for `examples/VaultState.sol` omits most state variables (e.g. `_donatedAssets`, `_totalShares`) while showing only `mapping` fields (`_exitRequests`, `_balances`).

## User Scenarios & Testing

### User Story 1 - Sized integer and bool storage on graph (Priority: P1)

**Given** a contract declares `uint128`, `uint256`, and `bool` storage variables, **When** the graph is built, **Then** each variable appears as a `state` node under the contract compound.

**Why this priority**: Modern Solidity code overwhelmingly uses sized integers; missing them makes the state workspace unusable for vault-style contracts.

**Independent Test**: Parse a minimal fixture with `uint256 internal _donatedAssets` and assert the node exists in graph JSON.

**Acceptance Scenarios**:

1. **Given** `VaultState.sol`, **When** analyzed, **Then** `_donatedAssets`, `_totalShares`, `_totalAssets`, `_capacity` appear as state nodes.
2. **Given** existing `mapping` variables, **When** analyzed, **Then** `_exitRequests` and `_balances` still appear (no regression).

---

### User Story 2 - User-defined storage types (Priority: P2)

**Given** a contract declares `ExitQueue.History internal _exitQueue`, **When** the graph is built, **Then** `_exitQueue` appears as a state node.

**Independent Test**: Minimal fixture with `Lib.Type internal _slot;` pattern.

---

### Edge Cases

- `mapping` and `=>` must not be split incorrectly (existing behavior preserved).
- Duplicate detection when multiple patterns hit the same declaration line.
- `uint` without size suffix still recognized when used.

## Requirements

### Functional Requirements

- **FR-001**: `ContractReader.extract_variables` MUST detect state declarations whose type starts with `uint<N>`, `int<N>`, `bytes<N>`, or `bool`.
- **FR-002**: FR-001 MUST NOT break detection of `mapping`, `address`, and `string` storage.
- **FR-003**: Reader SHOULD detect `TypeName` or `Lib.TypeName` storage with `internal`/`private`/`public` visibility before the variable name.
- **FR-004**: Regression tests MUST include VaultState subset and a minimal synthetic Solidity fixture.

## Success Criteria

- **SC-001**: VaultState graph lists at least 10 state variables including `_donatedAssets` and `_exitQueue`.
- **SC-002**: No duplicate state nodes for the same variable name in one contract.
- **SC-003**: Existing Solidity adapter integration tests remain green.

## Assumptions

- State extraction stays heuristic (not full Solidity parser).
- Deprecated variables with comments remain included if syntactically valid declarations.
