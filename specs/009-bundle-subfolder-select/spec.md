# Feature Specification: Bundle Subfolder Selection

**Feature Branch**: `009-bundle-subfolder-select`

**Created**: 2026-05-24

**Input**: After selecting a large folder (e.g. `contracts/` with many subfolders), user must upload only a subset (e.g. two subfolders) into one combined graph artifact without manually splitting the tree on disk.

## User Scenarios & Testing

### User Story 1 - Pick subfolders before combined upload (Priority: P1)

**Given** combined graph mode and a folder upload with tree paths `contracts/vault/...` and `contracts/oracle/...` (and other siblings), **When** the user unchecks unwanted subfolders and uploads, **Then** only files under selected subfolders are sent in the bundle; relative paths are preserved.

**Why this priority**: Large monorepos are common; full-folder bundle blows limits and obscures the graph.

**Independent Test**: Vitest on path filter helpers; manual upload of a tree with 3+ sibling folders, select 2, confirm manifest member count and paths.

**Acceptance Scenarios**:

1. **Given** three sibling folders under a common root, **When** two are selected, **Then** uploaded bundle excludes files from the third.
2. **Given** all subfolders selected (default), **When** user uploads without changes, **Then** behavior matches today (full tree).
3. **Given** zero subfolders selected, **When** user submits, **Then** client blocks upload with a clear error.

---

### User Story 2 - Clear UX when no subfolder choice is needed (Priority: P2)

**Given** a flat multi-file pick or a folder with files in a single subtree (no sibling folders at bundle root), **When** preview is shown, **Then** subfolder checkboxes are hidden.

---

### Edge Cases

- Mixed flat files + folder paths: no subfolder UI (existing combined-mode validation).
- Selecting a subfolder includes all nested files under it (`vault/modules/X.sol`).
- Paths normalized with POSIX `/`; no `..` segments.

## Requirements

### Functional Requirements

- **FR-001**: Combined upload UI MUST offer subfolder checkboxes when staged tree paths share a root and have two or more immediate child folder names.
- **FR-002**: Default selection MUST include all immediate subfolders.
- **FR-003**: Upload MUST reject when no subfolder is selected.
- **FR-004**: Filter logic MUST live in testable pure functions (`frontend/src/lib/`).
- **FR-005**: Backend contract unchanged (`files` + `bundle_paths_json` subset is valid).

## Success Criteria

- **SC-001**: User can build a combined bundle from two of N sibling folders under one picked root.
- **SC-002**: Vitest covers root inference, subfolder listing, and filtering.
- **SC-003**: No regression for flat bundle or separate-artifact upload mode.

## Assumptions

- Immediate children of the inferred bundle root are sufficient for v1 (not arbitrary deep path multi-select).
- User re-picks folder to change the full tree; no multi-root merge in one session.
