# Feature Specification: Inheritance Cross-Type Call Graph

**Feature Branch**: `002-inheritance-cross-calls`

**Created**: 2026-05-21

**Input**: Fix (A) reversed `cross_type_call` direction for inherited internal calls, (B) resolve relative `./Contract.sol` imports when analyzing a single file, (C) regression tests on `ValidatorChild` / `RewardBase`.

## User Scenarios

### US1 - Correct call direction (P1)

**Given** `approveValidators` in `ValidatorChild` calls `_collateralize` from `RewardBase`, **When** both contracts are in the model, **Then** graph shows `approveValidators` -> `_collateralize` (caller to callee).

### US2 - Single-file with local imports (P1)

**Given** only `ValidatorChild.sol` is analyzed, **When** `./RewardBase.sol` exists beside it, **Then** parent contract is loaded and US1 edge appears without manual multi-file upload.

## Requirements

- **FR-001**: `cross_type_call` from `high_connections` MUST go from child function (caller) to parent function (callee).
- **FR-002**: `parse_source` MUST transitively load relative `*.sol` imports from disk for **single-file** analysis only (exclude node_modules-style `@` paths). Bundle folder uploads MUST NOT inline sibling members (avoids N× duplicate contract tiles).
- **FR-003**: No infinite import cycles; cap traversal depth.
- **FR-004**: Tests on `tests/fixtures/solidity/cross_type/ValidatorChild.sol` assert edge direction and single-file resolution.

## Success Criteria

- **SC-001**: Merged or single-file-validators analysis yields `cross_type_call` from `approveValidators` to `_collateralize`.
- **SC-002**: Single-file validators-only ingest produces the same edge when `RewardBase.sol` is on disk.
