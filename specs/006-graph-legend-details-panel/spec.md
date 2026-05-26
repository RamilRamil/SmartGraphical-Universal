# Feature Specification: Graph Legend and Details Panel Clarity

**Feature Branch**: `006-graph-legend-details-panel`

**Created**: 2026-05-24

**Input**: (A) Orange function borders lack legend explanation; (B) side panel Import usage and Code sections overflow or render crooked.

## User Scenarios

### US1 - Understand function border colors (P1)

**Given** full graph with Solidity functions, **When** user sees orange or red borders on function nodes, **Then** legend or node guide explains: orange = public/external entrypoint; red = state writer; thicker orange = entrypoint that writes state.

### US2 - Readable import usage block (P1)

**Given** a function with import_dependency edges, **When** user selects it, **Then** Import usage list stays inside the side panel with path, lines, and callsite code blocks wrapping without horizontal overflow.

### US3 - Readable Code block (P1)

**Given** a function with full_source, **When** user opens Code in the side panel, **Then** preformatted source scrolls inside the panel width without breaking the grid layout.

## Requirements

- **FR-001**: Nodes legend MUST document function border semantics (entrypoint, state writer).
- **FR-002**: Side panel detail lists MUST use block layout for import rows (not horizontal flex with embedded pre).
- **FR-003**: `.sg-graph__meta dd` and code blocks MUST constrain width (`min-width: 0`, scroll/wrap).
- **FR-004**: Selected node panel MAY show border role hint when function is entrypoint or state writer.

## Success Criteria

- **SC-001**: Legend includes entrypoint orange border guide visible without hover-only tooltips.
- **SC-002**: Import usage with long path + callsite does not overflow side panel in 380px column fixture.
- **SC-003**: No frontend test regressions.
