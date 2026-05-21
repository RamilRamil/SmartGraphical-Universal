# Feature Specification: Accurate Solidity State Write Detection

**Feature Branch**: `001-fix-solidity-state-writes`

**Created**: 2026-05-21

**Status**: Planned (Variant B: writes fix + read/write graph edges)

**Plan**: [plan.md](./plan.md)

**Input**: User description: "Fix SmartGraphical so the graph and rules do not report state writes (e.g. mapping `rewards`) in Solidity `view`/`pure` functions and other read-only paths. Address false positives from comparison operators (`!=`), local variables loaded from storage, and substring matching between state variable names (e.g. `rewards` inside `rewardsNonce`)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Trustworthy write highlighting on graphs (Priority: P1)

A security reviewer opens the contract graph for a Solidity vault/rewards module (e.g. `KeeperRewards`) and enables state-write highlighting. They select `view` helpers such as `isCollateralized`, `canHarvest`, and `isHarvestRequired`.

**Why this priority**: Incorrect write signals directly undermine the primary value of the visualization during audits.

**Independent Test**: Analyze a fixture containing `KeeperRewards`-like patterns; confirm highlighted writers match functions that actually mutate the targeted state variable, and `view`/`pure` readers are not highlighted as writers.

**Acceptance Scenarios**:

1. **Given** a `view` function that only returns `rewards[vault].nonce != 0`, **When** the graph is built, **Then** `rewards` is not listed under that function's state writes and the function is not styled as a state writer.
2. **Given** a `view` function that copies `rewards[vault].nonce` into a local variable, **When** the graph is built, **Then** that copy is classified as a read, not a write to `rewards`.
3. **Given** a non-view function that assigns `rewards[vault] = ...` or mutates via a `storage` reference to `rewards[...]`, **When** the graph is built, **Then** those paths are still reported as writes to `rewards`.

---

### User Story 2 - Distinct read vs write linkage (Priority: P2)

A reviewer selects the state node `rewards` and inspects which functions touch it. The UI distinguishes functions that only read the variable from functions that write it.

**Why this priority**: Today, `state_to_function` edges conflate access types; reviewers cannot tell read-only usage from mutation without opening source.

**Independent Test**: For a contract with both read-only and write paths to the same state variable, the graph exposes separate read and write relationships (or clearly labeled edge kinds / panels).

**Acceptance Scenarios**:

1. **Given** `isCollateralized` reads `rewards` and `harvest` writes `rewards`, **When** the user inspects state `rewards`, **Then** both functions appear as readers, but only `harvest` appears as a writer.
2. **Given** inter-contract inheritance edges exist, **When** a child contract reads parent state via `cross_type_state`, **Then** the edge kind or metadata still reflects read vs write accurately.

---

### User Story 3 - Reliable rule findings (Priority: P2)

A reviewer runs Solidity rules that depend on `mutations` / `state_writes` (e.g. unguarded state mutation, outer calls). Findings should not fire on `view`/`pure` false positives.

**Why this priority**: False alerts waste review time and reduce trust in automated checks.

**Independent Test**: Run the rule suite on fixtures with known false-positive patterns; expect zero alerts attributing writes to `view` functions that only read state.

**Acceptance Scenarios**:

1. **Given** `isHarvestRequired` with only read patterns and comparisons involving `rewardsNonce`, **When** rules scan mutations, **Then** no alert claims `rewards` was written inside that function.
2. **Given** `updateRewards` writes `rewardsRoot` / `rewardsNonce` but not mapping `rewards`, **When** rules evaluate `rewards`, **Then** `updateRewards` is not counted as mutating `rewards`.

---

### Edge Cases

- State variables whose names are prefixes of other identifiers (`rewards` vs `rewardsNonce`, `rewardsRoot`, `rewardsDelay`).
- Compound assignment and update operators (`+=`, `-=`, `++`) on mapping entries or struct fields.
- Writes through `storage` pointers (`Reward storage r = rewards[msg.sender]; r.nonce = ...`).
- `pure` functions with no storage access (must never emit writes).
- Multiline statements and `unchecked` blocks after `;`-splitting.
- Contracts with no `view` functions (regression: existing true positives unchanged).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The analyzer MUST NOT classify a statement as mutating state variable `V` when the statement only performs comparison (`==`, `!=`, `<`, `<=`, `>`, `>=`) involving `V` or its fields.
- **FR-002**: The analyzer MUST NOT classify loading a value from `V` into a local variable (e.g. `uint256 x = V[key].field`) as a write to `V`.
- **FR-003**: The analyzer MUST match state variable identifiers as whole tokens (word boundaries), not as substrings of longer identifiers.
- **FR-004**: Functions explicitly marked `view` or `pure` MUST NOT produce `state_writes` / `mutations` entries for storage variables unless a documented, reviewed exception applies (default: none).
- **FR-005**: True storage writes MUST remain detectable, including assignment to `V[...]`, struct field updates via `storage` references bound to `V[...]`, and compound assignments targeting `V`.
- **FR-006**: The graph payload MUST allow consumers to distinguish read access from write access for each function–state pair (via separate lists, edge kinds, or equivalent metadata documented in the plan).
- **FR-007**: Rule engines consuming normalized `mutations` MUST inherit the corrected classification without requiring per-rule hotfixes for the known false-positive patterns.
- **FR-008**: Regression fixtures MUST cover at least: `KeeperRewards`-style `view` readers, prefix-collision names, and a positive control with real `rewards` writes in `harvest` / internal collateralize paths.

### Key Entities

- **State variable**: Named contract storage entity shown on the graph (e.g. `rewards`).
- **Function access record**: Per-function classification of read vs write statements referencing a state variable.
- **Graph function node**: Carries `state_reads`, `state_writes`, and optional write-path hints for UI highlighting.
- **Normalized mutation**: Statement text attached to a function used by Solidity rules.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the `KeeperRewards` reference fixture, 100% of `view`/`pure` functions that only read `rewards` have empty `state_writes` for `rewards`.
- **SC-002**: In the same fixture, 100% of functions that actually update `rewards` storage (`harvest`, `_collateralize`) retain non-empty `state_writes` for `rewards`.
- **SC-003**: Prefix-collision cases (`rewardsNonce`, `rewardsRoot`, etc.) produce zero spurious `rewards` write entries in functions that only touch those distinct variables.
- **SC-004**: Automated regression tests added for this feature pass in CI with no degradation of existing Solidity adapter unit tests.
- **SC-005**: Reviewer task time: a documented smoke checklist (graph + rules on fixture) completes without manual false-positive filtering for the listed `view` functions.

## Assumptions

- Scope is limited to the Solidity adapter path (`smartgraphical/adapters/solidity/adapter.py` and related helpers); C/Rust adapters are out of scope unless explicitly added in planning.
- Heuristic parsing remains acceptable; full Solidity AST parsing is not required for v1 if word-boundary and operator rules resolve the documented false positives.
- `KeeperRewards.sol` (or an extracted minimal fixture) is the canonical acceptance example discussed with the user.
- Git feature branch creation via Spec Kit hooks may be done by the user separately if automated hooks are not run in this session.
- Frontend changes are limited to consuming improved read/write metadata; large UI redesign is out of scope.

## Out of Scope (v1)

- Proving storage semantics for all possible Solidity patterns (e.g. inline assembly, delegatecall storage aliasing).
- Renaming state variables in user contracts to avoid name collisions.
- Changing business logic of example contracts (`KeeperRewards`).
