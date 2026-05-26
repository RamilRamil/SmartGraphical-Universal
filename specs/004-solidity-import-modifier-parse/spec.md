# Feature Specification: Solidity Import Graph and Override Modifier Parsing

**Feature Branch**: `004-solidity-import-modifier-parse`

**Created**: 2026-05-24

**Input**: Fix (A) duplicate contract tile on Show imports for `examples/EthMetaVault.sol`, (B) split/malformed `override(...)` and signature tokens shown as modifier nodes.

## User Scenarios

### US1 - No phantom contract on Show imports (P1)

**Given** single-file analysis of `EthMetaVault.sol`, **When** user toggles **Show imports**, **Then** exactly one `EthMetaVault` type compound exists and unused file-level import edges originate from `type:EthMetaVault`, not a separate `external:EthMetaVault` stub.

**Why this priority**: Duplicate contract tiles break import overview and suggest a second unknown contract.

**Independent Test**: Graph payload has no node with `id=external:EthMetaVault` and no `group=external` node labeled `EthMetaVault`.

---

### US2 - Correct override modifier display (P1)

**Given** functions with `override(ParentA, ParentB)` or `reinitializer(_version)` in signature, **When** graph is built, **Then** modifier badges and modifier nodes do not contain split tokens like `override(VaultImmutables,` or `VaultSubVaults)`; signature keywords (`internal`, `virtual`, bare `override`) are not promoted to modifier graph nodes.

**Independent Test**: Unit test on representative header; graph for `EthMetaVault.sol` has no modifier node whose label contains an unmatched `(`.

---

### US3 - Regression on existing Solidity fixtures (P2)

**Given** keeper inheritance tests and serializer unit tests, **When** full test suite runs, **Then** no regressions in cross-type call direction or graph schema validation.

## Edge Cases

- Constructor `override` without parent list stays a single token.
- `nonReentrant`, `onlyInitializing`, and declared `modifier` names remain visible modifier nodes.
- `@inheritdoc Parent` in `full_source` may still link used import symbols to functions; out of scope unless it creates duplicate type nodes.

## Requirements

### Functional Requirements

- **FR-001**: Unused `import_dependency` edges MUST resolve source endpoint to the owning type node when caller function name equals contract name (contract-level import wiring).
- **FR-002**: `ContractReader.extract_fparams` MUST tokenize post-parameter signature tail with parenthesis-aware splitting so `override(A, B)` and `reinitializer(_version)` are single tokens.
- **FR-003**: Graph serializer MUST NOT create modifier nodes for Solidity signature keywords or parenthesized `override(...)` annotations.
- **FR-004**: Regression tests MUST cover EthMetaVault import graph and override tokenization.

### Key Entities

- **import_dependency edge**: Links consumer type/function to imported symbol or `external_import` node.
- **modifier node**: Declared or applied modifier (`nonReentrant`), not visibility/state mutability keywords.

## Success Criteria

- **SC-001**: `examples/EthMetaVault.sol` graph has zero `external:EthMetaVault` / duplicate external contract nodes.
- **SC-002**: No modifier node label matches `override\\([^)]*,$` or ends with `)` without opening `override(`.
- **SC-003**: New unit tests pass; existing Solidity/serializer tests remain green.

## Assumptions

- Fix is parser + serializer only; no frontend change required for US1/US2.
- Single-file analysis mode (`expand_local_imports=True` default) uses same edge resolution rules.
